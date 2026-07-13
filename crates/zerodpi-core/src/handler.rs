//! Stateful packet handler implementing the SNI-spoofing state machine.
//!
//! Backends call [`Handler::on_packet`] for every captured TCP/IPv4 packet
//! that matches the per-target filter. The handler:
//! - Looks up the flow's 4-tuple in the shared [`FlowTable`].
//! - Tracks `syn_seq` / `syn_ack_seq` exactly as upstream does.
//! - On the first outbound bare ACK after the handshake, asks the active
//!   [`crate::methods::BypassMethod`] to stage payload mutations and returns
//!   [`crate::interceptor::Verdict::AcceptModified`].
//! - On the inbound ACK that acknowledges the spoofed segment, after first-data
//!   mutation, or immediately for methods that cannot expect a server ACK,
//!   signals the waiting proxy task via the flow's `Notify`.
//! - Any unexpected packet for a tracked flow is forwarded but the flow is
//!   marked closed (mirroring upstream's `on_unexpected_packet`).
//!
//! Packets for unknown flows are always passed through unchanged.

use std::sync::Arc;
use tracing::{debug, trace};

use super::flow::{BypassOutcome, FlowEntry, FlowKey, FlowTable};
use super::interceptor::{Direction, PacketHandler, PacketView, Verdict};
use super::methods::{BypassMethod, MethodAction};

pub struct Handler {
    flows: FlowTable,
    method: Arc<dyn BypassMethod>,
}

impl Handler {
    pub fn new(flows: FlowTable, method: Arc<dyn BypassMethod>) -> Self {
        Self { flows, method }
    }

    fn flow_key_for(&self, pkt: &PacketView<'_>) -> FlowKey {
        // The flow table is keyed on the *outbound* direction.
        match pkt.direction {
            Direction::Outbound => FlowKey {
                src_ip: pkt.src_ip,
                src_port: pkt.src_port,
                dst_ip: pkt.dst_ip,
                dst_port: pkt.dst_port,
            },
            Direction::Inbound => FlowKey {
                src_ip: pkt.dst_ip,
                src_port: pkt.dst_port,
                dst_ip: pkt.src_ip,
                dst_port: pkt.src_port,
            },
        }
    }

    fn unexpected(
        &self,
        entry: &FlowEntry,
        state: &mut super::flow::FlowState,
        pkt: &PacketView<'_>,
        why: &str,
    ) -> Verdict {
        debug!(?pkt.direction, why, "unexpected packet; closing flow");
        if state.outcome.is_none() {
            state.outcome = Some(BypassOutcome::UnexpectedClose);
            state.monitor = false;
            entry.notify.notify_waiters();
        }
        Verdict::Accept
    }
}

impl PacketHandler for Handler {
    fn on_packet(&mut self, pkt: &mut PacketView<'_>) -> Verdict {
        let key = self.flow_key_for(pkt);
        let entry = match self.flows.get(&key).map(|e| e.clone()) {
            Some(e) => e,
            None => return Verdict::Accept,
        };
        let mut state = entry.state.lock();
        if !state.monitor {
            return Verdict::Accept;
        }

        match pkt.direction {
            Direction::Outbound => {
                if pkt.is_bare_syn() {
                    if pkt.ack != 0 {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound SYN with non-zero ack_num",
                        );
                    }
                    if let Some(prev) = state.syn_seq {
                        if prev != pkt.seq {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "outbound SYN seq changed (retransmit?)",
                            );
                        }
                    }
                    state.syn_seq = Some(pkt.seq);
                    return Verdict::Accept;
                }
                if pkt.is_bare_ack() {
                    if state.fake_sent || state.waiting_for_data {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound packet after fake already sent",
                        );
                    }
                    let syn_seq = match state.syn_seq {
                        Some(s) => s,
                        None => {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "outbound ACK before SYN seen",
                            )
                        }
                    };
                    if pkt.seq != syn_seq.wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound ACK seq does not match syn_seq+1",
                        );
                    }
                    let syn_ack_seq = match state.syn_ack_seq {
                        Some(s) => s,
                        None => {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "outbound ACK before SYN-ACK",
                            )
                        }
                    };
                    if pkt.ack != syn_ack_seq.wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound ACK ack_num does not match syn_ack_seq+1",
                        );
                    }
                    // Hand the ACK to the active bypass method to stage mutations.
                    match self.method.on_handshake_complete_ack(&state, pkt) {
                        MethodAction::EmitFakeAndAccept {
                            complete_immediately,
                            continue_with_data,
                        } => {
                            state.fake_sent = true;
                            trace!(method = self.method.name(), "emitting fake (modified ACK)");
                            if continue_with_data {
                                state.waiting_for_data = true;
                                entry.ready_for_data.notify_waiters();
                            } else if complete_immediately {
                                drop(state);
                                entry.finish(BypassOutcome::FakeDataAcked);
                            }
                            return Verdict::AcceptModified;
                        }
                        MethodAction::PassThrough => {
                            // Method deferred to the first data packet (e.g. tls_record_frag).
                            state.waiting_for_data = true;
                            entry.ready_for_data.notify_waiters();
                            trace!(
                                method = self.method.name(),
                                "deferring bypass to first data packet"
                            );
                            return Verdict::Accept;
                        }
                        MethodAction::CompleteAndAccept => {
                            drop(state);
                            entry.finish(BypassOutcome::FakeDataAcked);
                            return Verdict::Accept;
                        }
                        MethodAction::AbortAndAccept => {
                            drop(state);
                            entry.finish(BypassOutcome::UnexpectedClose);
                            return Verdict::Accept;
                        }
                    }
                }
                // First outbound data packet when method deferred to this stage.
                if pkt.payload_len > 0 && state.waiting_for_data && !state.first_data_modified {
                    match self.method.on_first_data_packet(&state, pkt) {
                        MethodAction::EmitFakeAndAccept {
                            complete_immediately,
                            continue_with_data: _,
                        } => {
                            state.first_data_modified = true;
                            state.waiting_for_data = false;
                            trace!(
                                method = self.method.name(),
                                "fragmented first data packet; signalling bypass complete"
                            );
                            if complete_immediately {
                                // Signal completion immediately — no inbound ACK needed.
                                drop(state);
                                entry.finish(BypassOutcome::FakeDataAcked);
                            }
                            return Verdict::AcceptModified;
                        }
                        MethodAction::CompleteAndAccept => {
                            state.first_data_modified = true;
                            state.waiting_for_data = false;
                            drop(state);
                            entry.finish(BypassOutcome::FakeDataAcked);
                            return Verdict::Accept;
                        }
                        MethodAction::PassThrough => return Verdict::Accept,
                        MethodAction::AbortAndAccept => {
                            state.first_data_modified = true;
                            state.waiting_for_data = false;
                            drop(state);
                            entry.finish(BypassOutcome::UnexpectedClose);
                            return Verdict::Accept;
                        }
                    }
                }
                self.unexpected(&entry, &mut state, pkt, "unexpected outbound packet")
            }
            Direction::Inbound => {
                if state.syn_seq.is_none() {
                    return self.unexpected(
                        &entry,
                        &mut state,
                        pkt,
                        "inbound packet before any outbound SYN",
                    );
                }
                if pkt.is_syn_ack() {
                    if pkt.ack != state.syn_seq.unwrap().wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "inbound SYN-ACK ack_num does not match syn_seq+1",
                        );
                    }
                    if let Some(prev) = state.syn_ack_seq {
                        if prev != pkt.seq {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "inbound SYN-ACK seq changed (retransmit?)",
                            );
                        }
                    }
                    state.syn_ack_seq = Some(pkt.seq);
                    return Verdict::Accept;
                }
                if pkt.is_bare_ack() && state.fake_sent {
                    let syn_ack_seq = state.syn_ack_seq.expect("checked above via syn_seq");
                    if pkt.seq != syn_ack_seq.wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "inbound post-fake ACK seq mismatch",
                        );
                    }
                    if pkt.ack != state.syn_seq.unwrap().wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "inbound post-fake ACK ack mismatch",
                        );
                    }
                    if state.waiting_for_data {
                        trace!(
                            method = self.method.name(),
                            "accepted post-fake ACK while waiting for first data packet"
                        );
                        return Verdict::Accept;
                    }
                    drop(state);
                    entry.finish(BypassOutcome::FakeDataAcked);
                    return Verdict::Accept;
                }
                self.unexpected(&entry, &mut state, pkt, "unexpected inbound packet")
            }
        }
    }
}
