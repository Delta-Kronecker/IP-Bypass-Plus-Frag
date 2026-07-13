//! Pluggable bypass methods for ip_bypass_plus mode.
//!
//! Only two methods are supported:
//! - `tls_record_frag`: TLS Record Fragment via packet interceptor.
//! - `tls_frag`: TCP-level TLS Fragment via socket writes (no interceptor).

pub mod tcp_segmentation;
pub mod tls_record_frag;

use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

/// Result of asking a method to act on a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodAction {
    /// Apply the staged mutations on `PacketView` and accept it.
    EmitFakeAndAccept {
        complete_immediately: bool,
        continue_with_data: bool,
    },
    /// Forward unchanged and mark the bypass phase complete.
    CompleteAndAccept,
    /// Forward unchanged.
    PassThrough,
    /// Forward unchanged and mark the bypass phase failed.
    AbortAndAccept,
}

impl MethodAction {
    pub const fn emit_and_wait_for_ack() -> Self {
        Self::EmitFakeAndAccept {
            complete_immediately: false,
            continue_with_data: false,
        }
    }

    pub const fn emit_and_complete() -> Self {
        Self::EmitFakeAndAccept {
            complete_immediately: true,
            continue_with_data: false,
        }
    }

    pub const fn emit_and_wait_for_data() -> Self {
        Self::EmitFakeAndAccept {
            complete_immediately: false,
            continue_with_data: true,
        }
    }

    pub const fn complete_and_accept() -> Self {
        Self::CompleteAndAccept
    }

    pub const fn abort_and_accept() -> Self {
        Self::AbortAndAccept
    }
}

/// A pluggable DPI-bypass technique.
pub trait BypassMethod: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction;

    fn on_first_data_packet(&self, _flow: &FlowState, _pkt: &mut PacketView<'_>) -> MethodAction {
        MethodAction::PassThrough
    }
}

/// Build an interceptor-based method from the application config.
pub fn build_method(cfg: &Config) -> Option<Box<dyn BypassMethod>> {
    match cfg.BYPASS_METHOD.as_str() {
        "tls_record_frag" => Some(Box::new(tls_record_frag::TlsRecordFrag::new(cfg))),
        // "tls_frag" is socket-based and handled directly in proxy.rs.
        _ => None,
    }
}
