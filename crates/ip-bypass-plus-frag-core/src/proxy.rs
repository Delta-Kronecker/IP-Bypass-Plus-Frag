//! tokio-based TCP proxy for ip_bypass_plus mode.
//!
//! For `tls_record_frag`:
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Open an outbound TCP socket bound to the local interface IP.
//! 3. Register the flow in the [`FlowTable`] (with empty fake payload).
//! 4. The platform interceptor observes the handshake and asks the proxy
//!    to write the first ClientHello while the flow is still being intercepted.
//! 5. The interceptor fragments the real ClientHello into TLS record fragments.
//! 6. Once the bypass completes, the proxy runs a normal bidirectional copy.
//!
//! For `tls_frag` (socket-based):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Connect to the upstream server (no FlowTable registration, no interceptor).
//! 3. In `tlshello` mode, read one complete TLS record and write it in chunks.
//! 4. In packet-range mode, let the relay fragment selected client writes.
//! 5. Relay the rest of the session normally.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::{Config, TlsFragPackets};
use crate::flow::{BypassOutcome, FlowEntry, FlowKey, FlowTable};
use crate::methods::tcp_segmentation::{read_one_tls_record, write_fragmented, TcpSegmentation};

pub const CONNECT_PORT: u16 = 443;

/// A single IP in the rotation pool.
#[derive(Debug, Clone)]
pub struct IpPoolEntry {
    pub ip: IpAddr,
    pub score: u8,
}

/// IP pool for multi-IP mode.
#[derive(Debug)]
pub struct IpPool {
    entries: Vec<IpPoolEntry>,
    index: AtomicU64,
}

impl IpPool {
    pub fn new(entries: Vec<IpPoolEntry>) -> Self {
        Self {
            entries,
            index: AtomicU64::new(0),
        }
    }

    /// Return the next IP in round-robin order.
    pub fn next(&self) -> Option<IpAddr> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.entries.len() as u64;
        Some(self.entries[idx as usize].ip)
    }

    pub fn entries(&self) -> &[IpPoolEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug)]
pub enum ProxyEvent {
    ListenerStarted {
        mode: String,
        listen_addr: SocketAddr,
    },
    ConnectionAccepted { peer: SocketAddr, src_port: u16, upstream_ip: IpAddr },
    BypassComplete {
        src_port: u16,
        outcome: BypassOutcome,
    },
    RelayFinished {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
        reason: RelayEndReason,
    },
    ConnectionError { src_port: u16, error: String },
    RelayProgress {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
    },
    IpTargetChanged { ip: IpAddr },
}

pub type ProxyEventSender = mpsc::UnboundedSender<ProxyEvent>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEndReason {
    Completed,
    MaxLifetime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayResult {
    c2s_bytes: u64,
    s2c_bytes: u64,
    reason: RelayEndReason,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tcp_segmentation: TcpSegmentation,
}

impl ConnectionSettings {
    fn from_config(cfg: &Config) -> Self {
        let tcp_segmentation = TcpSegmentation::new(cfg);
        Self {
            bypass_timeout: Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS),
            max_lifetime: configured_relay_max_lifetime(cfg),
            segment_first_client_hello: method_segments_first_client_hello(&cfg.BYPASS_METHOD),
            tcp_segmentation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BypassProgress {
    ReadyForData,
    Complete(BypassOutcome),
}

#[derive(Debug)]
struct InterceptConnectionTarget {
    interface_ip: Ipv4Addr,
    connect_ip: Ipv4Addr,
}

fn emit(tx: &Option<ProxyEventSender>, event: ProxyEvent) {
    if let Some(ref tx) = tx {
        let _ = tx.send(event);
    }
}

fn configured_relay_max_lifetime(cfg: &Config) -> Option<Duration> {
    (cfg.RELAY_MAX_LIFETIME_SECS > 0).then(|| Duration::from_secs(cfg.RELAY_MAX_LIFETIME_SECS))
}

async fn read_one_client_write(src: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; 64 * 1024];
    let n = src
        .read(&mut buf)
        .await
        .context("reading client data write")?;
    if n == 0 {
        anyhow::bail!("client closed before sending data");
    }
    buf.truncate(n);
    Ok(buf)
}

async fn write_client_data<W>(
    dst: &mut W,
    data: &[u8],
    segmentation: TcpSegmentation,
    write_index: u32,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if segmentation.fragments_write(write_index) {
        write_fragmented(dst, data, segmentation.length, segmentation.interval_ms).await
    } else {
        dst.write_all(data).await.context("writing client data")?;
        dst.flush().await.context("flushing client data")?;
        Ok(())
    }
}

async fn read_client_tls_record_with_timeout(
    incoming: &mut TcpStream,
    timeout: Duration,
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
) -> anyhow::Result<Vec<u8>> {
    match tokio::time::timeout(timeout, read_one_tls_record(incoming)).await {
        Ok(Ok(record)) => Ok(record),
        Ok(Err(e)) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            Err(e).context("reading ClientHello from client")
        }
        Err(_) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("timed out reading ClientHello from client");
        }
    }
}

async fn read_client_write_with_timeout(
    incoming: &mut TcpStream,
    timeout: Duration,
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
) -> anyhow::Result<Vec<u8>> {
    match tokio::time::timeout(timeout, read_one_client_write(incoming)).await {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            Err(e).context("reading client data from client")
        }
        Err(_) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("timed out reading client data from client");
        }
    }
}

fn current_bypass_progress(entry: &FlowEntry) -> Option<BypassProgress> {
    let state = entry.state.lock();
    if let Some(outcome) = state.outcome {
        Some(BypassProgress::Complete(outcome))
    } else if state.waiting_for_data {
        Some(BypassProgress::ReadyForData)
    } else {
        None
    }
}

fn method_segments_first_client_hello(method: &str) -> bool {
    method == "tls_record_frag"
}

async fn wait_for_initial_bypass_progress(
    entry: &FlowEntry,
    timeout: Duration,
) -> Option<BypassProgress> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(progress) = current_bypass_progress(entry) {
                return progress;
            }
            tokio::select! {
                _ = entry.notify.notified() => {}
                _ = entry.ready_for_data.notified() => {}
            }
        }
    })
    .await
    .ok()
}

async fn wait_for_bypass_completion(entry: &FlowEntry, timeout: Duration) -> Option<BypassOutcome> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(outcome) = entry.state.lock().outcome {
                return outcome;
            }
            entry.notify.notified().await;
        }
    })
    .await
    .ok()
}

fn finish_bypass_or_error(
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    outcome: Option<BypassOutcome>,
    timeout_error: &'static str,
) -> anyhow::Result<()> {
    match outcome {
        Some(BypassOutcome::FakeDataAcked) => {
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::FakeDataAcked,
                },
            );
            Ok(())
        }
        Some(BypassOutcome::UnexpectedClose) => {
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("interceptor closed the flow");
        }
        None => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!(timeout_error);
        }
    }
}

fn scopeguard<F: FnOnce()>(f: F) -> ScopeGuard<F> {
    ScopeGuard(Some(f))
}
struct ScopeGuard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

// ---------------------------------------------------------------------------
// IP-bypass-plus proxy
// ---------------------------------------------------------------------------

pub async fn run_ip_bypass_plus_proxy(
    cfg: Arc<Config>,
    active_ip: Arc<RwLock<IpAddr>>,
    interface_ip: Ipv4Addr,
    flows: FlowTable,
    event_tx: Option<ProxyEventSender>,
    ip_pool: Option<Arc<IpPool>>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, method = %cfg.BYPASS_METHOD, "ip_bypass_plus: listening");
    emit(
        &event_tx,
        ProxyEvent::ListenerStarted {
            mode: cfg.MODE.clone(),
            listen_addr,
        },
    );

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "ip_bypass_plus: accept failed");
                continue;
            }
        };
        debug!(%peer, "ip_bypass_plus: accepted");

        let connect_ip = if let Some(ref pool) = ip_pool {
            match pool.next() {
                Some(ip) => match ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(v6) => {
                        warn!(%v6, "ip_bypass_plus: pool IPv6 target rejected");
                        continue;
                    }
                },
                None => {
                    warn!("ip_bypass_plus: pool is empty");
                    continue;
                }
            }
        } else {
            match *active_ip.read().unwrap() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(ip) => {
                    warn!(%ip, "ip_bypass_plus: active IPv6 target rejected");
                    continue;
                }
            }
        };

        if cfg.BYPASS_METHOD == "tls_frag" {
            let cfg = cfg.clone();
            let event_tx = event_tx.clone();
            let pool = ip_pool.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_seg_connection_with_ip(cfg, connect_ip, incoming, peer, event_tx, pool)
                        .await
                {
                    warn!(%peer, error = %e, "ip_bypass_plus tls_frag connection failed");
                }
            });
            continue;
        }

        let flows = flows.clone();
        let event_tx = event_tx.clone();
        let pool = ip_pool.clone();
        let connection_settings = ConnectionSettings::from_config(&cfg);
        tokio::spawn(async move {
            if let Err(e) = handle_intercept_connection(
                InterceptConnectionTarget {
                    interface_ip,
                    connect_ip,
                },
                flows,
                incoming,
                peer,
                event_tx,
                connection_settings,
                pool,
            )
            .await
            {
                warn!(%peer, error = %e, "ip_bypass_plus connection failed");
            }
        });
    }
}

async fn handle_intercept_connection(
    target: InterceptConnectionTarget,
    flows: FlowTable,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
    settings: ConnectionSettings,
    ip_pool: Option<Arc<IpPool>>,
) -> anyhow::Result<()> {
    let connect_port = CONNECT_PORT;
    let interface_ip = target.interface_ip;
    let connect_ip = target.connect_ip;

    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((interface_ip, 0)))?;
    let local = socket.local_addr()?;
    let src_port = local.port();

    let key = FlowKey {
        src_ip: interface_ip,
        src_port,
        dst_ip: connect_ip,
        dst_port: connect_port,
    };

    let entry = FlowEntry::new(Vec::new());
    flows.insert(key, entry.clone());

    let cleanup = scopeguard(|| {
        flows.remove(&key);
    });

    let mut outgoing = match socket
        .connect(SocketAddr::from((connect_ip, connect_port)))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("connect upstream");
        }
    };

    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port, upstream_ip: IpAddr::from(connect_ip) });

    let mut client_fragmentation_after_prefix = None;

    match wait_for_initial_bypass_progress(&entry, settings.bypass_timeout).await {
        Some(BypassProgress::Complete(outcome)) => {
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                Some(outcome),
                "bypass timed out",
            )?;
        }
        Some(BypassProgress::ReadyForData) => {
            if settings.segment_first_client_hello {
                let segmentation = settings.tcp_segmentation;
                if segmentation.nodelay {
                    outgoing
                        .set_nodelay(true)
                        .context("tls_record_frag: set_nodelay on upstream socket")?;
                }

                match segmentation.packets {
                    TlsFragPackets::TlsHello => {
                        let client_hello = read_client_tls_record_with_timeout(
                            &mut incoming,
                            settings.bypass_timeout,
                            &entry,
                            &event_tx,
                            src_port,
                        )
                        .await?;
                        if let Err(e) = write_fragmented(
                            &mut outgoing,
                            &client_hello,
                            segmentation.length,
                            segmentation.interval_ms,
                        )
                        .await
                        {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e)
                                .context("tls_record_frag: writing fragmented ClientHello");
                        }
                    }
                    TlsFragPackets::WriteRange { .. } => {
                        let client_data = read_client_write_with_timeout(
                            &mut incoming,
                            settings.bypass_timeout,
                            &entry,
                            &event_tx,
                            src_port,
                        )
                        .await?;
                        if let Err(e) =
                            write_client_data(&mut outgoing, &client_data, segmentation, 1).await
                        {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context("tls_record_frag: writing first client data");
                        }
                        client_fragmentation_after_prefix = Some((segmentation, 1));
                    }
                }
            } else {
                let client_hello = read_client_tls_record_with_timeout(
                    &mut incoming,
                    settings.bypass_timeout,
                    &entry,
                    &event_tx,
                    src_port,
                )
                .await?;

                if let Err(e) = outgoing.write_all(&client_hello).await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("writing ClientHello to upstream");
                }
                if let Err(e) = outgoing.flush().await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("flushing ClientHello to upstream");
                }
            }

            let outcome = wait_for_bypass_completion(&entry, settings.bypass_timeout).await;
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                outcome,
                "first data bypass timed out",
            )?;
        }
        None => {
            finish_bypass_or_error(&entry, &event_tx, src_port, None, "bypass timed out")?;
        }
    }

    debug!(?key, "bypass complete");

    drop(cleanup);

    let relay = counting_relay_with_client_fragmentation(
        incoming,
        outgoing,
        &event_tx,
        src_port,
        settings.max_lifetime,
        client_fragmentation_after_prefix,
    )
    .await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );

    Ok(())
}

async fn handle_tcp_seg_connection_with_ip(
    cfg: Arc<Config>,
    connect_ip: Ipv4Addr,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
    ip_pool: Option<Arc<IpPool>>,
) -> anyhow::Result<()> {
    let src_port = peer.port();

    let method = TcpSegmentation::new(&cfg);
    let connect_addr = SocketAddr::from((connect_ip, CONNECT_PORT));

    let mut outgoing = match TcpStream::connect(connect_addr).await {
        Ok(s) => s,
        Err(e) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("tls_frag: connect upstream");
        }
    };

    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port, upstream_ip: IpAddr::from(connect_ip) });

    if method.nodelay {
        outgoing
            .set_nodelay(true)
            .context("tls_frag: set_nodelay on upstream socket")?;
    }

    let client_fragmentation = match method.packets {
        TlsFragPackets::TlsHello => {
            let client_hello = read_one_tls_record(&mut incoming)
                .await
                .context("tls_frag: reading ClientHello from client")?;

            write_fragmented(
                &mut outgoing,
                &client_hello,
                method.length,
                method.interval_ms,
            )
            .await
            .context("tls_frag: writing fragmented ClientHello")?;

            debug!(
                length = %method.length,
                interval_ms = %method.interval_ms,
                nodelay = method.nodelay,
                total_bytes = client_hello.len(),
                "tls_frag: ClientHello written in fragments; handing off to relay"
            );
            None
        }
        TlsFragPackets::WriteRange { .. } => {
            debug!(
                packets = ?method.packets,
                length = %method.length,
                interval_ms = %method.interval_ms,
                nodelay = method.nodelay,
                "tls_frag: fragmenting selected client writes in relay"
            );
            Some((method, 0))
        }
    };

    emit(
        &event_tx,
        ProxyEvent::BypassComplete {
            src_port,
            outcome: BypassOutcome::FakeDataAcked,
        },
    );

    let relay = counting_relay_with_client_fragmentation(
        incoming,
        outgoing,
        &event_tx,
        src_port,
        configured_relay_max_lifetime(&cfg),
        client_fragmentation,
    )
    .await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "tls_frag: relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );
    Ok(())
}
// Counting relay
// ---------------------------------------------------------------------------

async fn counting_relay_with_client_fragmentation(
    incoming: TcpStream,
    outgoing: TcpStream,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    max_lifetime: Option<Duration>,
    client_fragmentation: Option<(TcpSegmentation, u32)>,
) -> RelayResult {
    let (inc_rd, inc_wr) = incoming.into_split();
    let (out_rd, out_wr) = outgoing.into_split();

    let c2s_atomic = Arc::new(AtomicU64::new(0));
    let s2c_atomic = Arc::new(AtomicU64::new(0));

    let mut c2s_task = tokio::spawn(copy_counting_client_to_server(
        inc_rd,
        out_wr,
        c2s_atomic.clone(),
        client_fragmentation,
    ));
    let mut s2c_task = tokio::spawn(copy_counting(out_rd, inc_wr, s2c_atomic.clone()));

    let ticker = event_tx.as_ref().map(|tx| {
        let tx = tx.clone();
        let c = c2s_atomic.clone();
        let s = s2c_atomic.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let _ = tx.send(ProxyEvent::RelayProgress {
                    src_port,
                    c2s_bytes: c.load(Ordering::Relaxed),
                    s2c_bytes: s.load(Ordering::Relaxed),
                });
            }
        })
    });

    let result = if let Some(max_lifetime) = max_lifetime {
        let mut c2s_done: Option<u64> = None;
        let mut s2c_done: Option<u64> = None;
        let deadline = tokio::time::sleep(max_lifetime);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    if c2s_done.is_none() {
                        c2s_task.abort();
                    }
                    if s2c_done.is_none() {
                        s2c_task.abort();
                    }
                    break RelayResult {
                        c2s_bytes: c2s_done.unwrap_or_else(|| c2s_atomic.load(Ordering::Relaxed)),
                        s2c_bytes: s2c_done.unwrap_or_else(|| s2c_atomic.load(Ordering::Relaxed)),
                        reason: RelayEndReason::MaxLifetime,
                    };
                }
                c2s_result = &mut c2s_task, if c2s_done.is_none() => {
                    c2s_done = Some(c2s_result.unwrap_or(0));
                    if let (Some(c2s_bytes), Some(s2c_bytes)) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: RelayEndReason::Completed,
                        };
                    }
                }
                s2c_result = &mut s2c_task, if s2c_done.is_none() => {
                    s2c_done = Some(s2c_result.unwrap_or(0));
                    if let (Some(c2s_bytes), Some(s2c_bytes)) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: RelayEndReason::Completed,
                        };
                    }
                }
            }
        }
    } else {
        let (c2s_result, s2c_result) = tokio::join!(c2s_task, s2c_task);
        RelayResult {
            c2s_bytes: c2s_result.unwrap_or(0),
            s2c_bytes: s2c_result.unwrap_or(0),
            reason: RelayEndReason::Completed,
        }
    };

    if let Some(t) = ticker {
        t.abort();
    }

    result
}

async fn copy_counting_client_to_server(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
    client_fragmentation: Option<(TcpSegmentation, u32)>,
) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let mut write_index = client_fragmentation.map(|(_, index)| index).unwrap_or(0);
    let segmentation = client_fragmentation.map(|(segmentation, _)| segmentation);

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        write_index = write_index.saturating_add(1);
        let write_result = if let Some(segmentation) = segmentation {
            write_client_data(&mut writer, &buf[..n], segmentation, write_index).await
        } else {
            writer
                .write_all(&buf[..n])
                .await
                .map_err(anyhow::Error::from)
        };

        if write_result.is_err() {
            break;
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

async fn copy_counting(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}
