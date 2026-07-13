//! IP Bypass Plus: IPv4 relay with real-SNI-preserving DPI bypass.
//!
//! Start-up flow:
//!   1. Load `config.toml`.
//!   2. Read `ip_list.txt` (or the path set in `IP_LIST`).
//!   3. If `SELECTED_IP` is set, skip scanning; use the IP directly.
//!   4. Otherwise scan all IPs concurrently (TCP → TLS → TTFB → speed) and
//!      show the ratatui progress view, then either auto-select the top result
//!      (`AUTO_SELECT = true`) or show the selection table.
//!   5. Start the tokio TCP proxy and, for `tls_record_frag`, the
//!      packet interceptor thread.
//!   6. If `RESCAN_INTERVAL_SECS > 0`, run the scanner again in the background
//!      every that many seconds and switch new connections to better targets.

mod runtime_events;
mod tui;

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use ipnet::IpNet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use ip_bypass_plus_frag_core::config::Config;
use ip_bypass_plus_frag_core::flow::new_flow_table;
use ip_bypass_plus_frag_core::handler::Handler;
use ip_bypass_plus_frag_core::interceptor::{FilterSpec, InterceptorShutdown, PacketInterceptor};
use ip_bypass_plus_frag_core::ip_scanner::{load_ip_list, scan_ip_list, IpProbeEntry, IpScanEvent};
use ip_bypass_plus_frag_core::methods::build_method;
use ip_bypass_plus_frag_core::net::default_interface_ipv4;
use ip_bypass_plus_frag_core::proxy::{
    run_ip_bypass_plus_proxy, IpPool, IpPoolEntry, ProxyEvent, ProxyEventSender, RelayEndReason,
    CONNECT_PORT,
};
use ip_bypass_plus_frag_platform::{ensure_packet_interception_access, DefaultInterceptor};

use runtime_events::{
    BypassStatus, RuntimeEvent, RuntimeEventEmitter, ScanKind, TargetKind, CONTRACT_VERSION,
};

#[derive(Clone, Copy)]
struct TuiAwareStderr;

enum TuiAwareStderrGuard {
    Stderr(io::Stderr),
    Sink(io::Sink),
}

impl Write for TuiAwareStderrGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TuiAwareStderrGuard::Stderr(stderr) => stderr.write(buf),
            TuiAwareStderrGuard::Sink(sink) => sink.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TuiAwareStderrGuard::Stderr(stderr) => stderr.flush(),
            TuiAwareStderrGuard::Sink(sink) => sink.flush(),
        }
    }
}

impl<'a> MakeWriter<'a> for TuiAwareStderr {
    type Writer = TuiAwareStderrGuard;

    fn make_writer(&'a self) -> Self::Writer {
        if tui::is_tui_active() {
            TuiAwareStderrGuard::Sink(io::sink())
        } else {
            TuiAwareStderrGuard::Stderr(io::stderr())
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about = "IP Bypass Plus Frag: IPv4 relay with real-SNI-preserving DPI bypass")]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long)]
    listen_host: Option<String>,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long)]
    auto_select: bool,
    #[arg(long)]
    no_tui: bool,
    #[arg(long)]
    json_events: bool,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    queue_num: Option<u16>,
    #[arg(long)]
    scan_timeout: Option<u64>,
    #[arg(long)]
    rescan_interval: Option<u64>,
    #[arg(long)]
    sni_switch_min_score: Option<u8>,
    #[arg(long)]
    bypass_timeout: Option<u64>,
    #[arg(long)]
    relay_max_lifetime: Option<u64>,
}

fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install ring CryptoProvider"))?;

    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(TuiAwareStderr)
        .with_ansi(!args.json_events)
        .with_level(true)
        .with_target(false)
        .init();

    let events = RuntimeEventEmitter::new(args.json_events);
    events.emit(RuntimeEvent::Startup {
        contract_version: CONTRACT_VERSION,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
    });

    let result = run(args, events.clone());
    if let Err(error) = &result {
        events.emit(RuntimeEvent::FatalError {
            message: format!("{error:#}"),
        });
    }
    result
}

fn run(args: Args, events: RuntimeEventEmitter) -> Result<()> {
    let no_tui = args.no_tui || args.json_events;
    if args.json_events && !args.no_tui {
        warn!("--json-events implies --no-tui");
    }

    let cfg_path = args.config.clone().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("config.toml")))
            .unwrap_or_else(|| PathBuf::from("config.toml"))
    });
    let mut cfg = Config::from_file(&cfg_path)
        .with_context(|| format!("loading config from {}", cfg_path.display()))?;

    if let Some(v) = args.listen_host {
        cfg.LISTEN_HOST = v;
    }
    if let Some(v) = args.listen_port {
        cfg.LISTEN_PORT = v;
    }
    if args.auto_select {
        cfg.AUTO_SELECT = true;
    }
    if let Some(v) = args.method {
        cfg.BYPASS_METHOD = v;
    }
    if let Some(v) = args.queue_num {
        cfg.NFQUEUE_NUM = v;
    }
    if let Some(v) = args.scan_timeout {
        cfg.SCAN_TIMEOUT_SECS = v;
    }
    if let Some(v) = args.rescan_interval {
        cfg.RESCAN_INTERVAL_SECS = v;
    }
    if let Some(v) = args.sni_switch_min_score {
        cfg.SNI_SWITCH_MIN_SCORE = v;
    }
    if let Some(v) = args.bypass_timeout {
        cfg.BYPASS_TIMEOUT_SECS = v;
    }
    if let Some(v) = args.relay_max_lifetime {
        cfg.RELAY_MAX_LIFETIME_SECS = v;
    }
    cfg.validate()?;

    let root_required = requires_packet_interception(&cfg);
    events.emit(RuntimeEvent::ConfigLoaded {
        path: cfg_path.display().to_string(),
        mode: cfg.MODE.clone(),
        bypass_method: cfg.BYPASS_METHOD.clone(),
        listen_host: cfg.LISTEN_HOST.clone(),
        listen_port: cfg.LISTEN_PORT,
        auto_select: cfg.AUTO_SELECT,
        no_tui,
        root_required,
    });
    if root_required {
        if let Err(error) = ensure_packet_interception_access() {
            events.emit(RuntimeEvent::RootRequired {
                mode: cfg.MODE.clone(),
                bypass_method: cfg.BYPASS_METHOD.clone(),
                message: root_required_message(&cfg),
                rootless_alternatives: rootless_alternatives(),
            });
            return Err(error).context(root_required_message(&cfg));
        }
    }
    let cfg = Arc::new(cfg);

    let ip_list_path = {
        let raw = PathBuf::from(&cfg.IP_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    return ip_bypass_plus_main(cfg, cfg_path, rt, no_tui, events, ip_list_path, scan_timeout);
}

fn requires_packet_interception(cfg: &Config) -> bool {
    cfg.MODE == "ip_bypass_plus" && cfg.BYPASS_METHOD != "tls_frag"
}

fn root_required_message(cfg: &Config) -> String {
    format!(
        "MODE = \"{}\" with BYPASS_METHOD = \"{}\" requires packet interception; on Android the app must start via su/root. Rootless alternative: BYPASS_METHOD = \"tls_frag\".",
        cfg.MODE, cfg.BYPASS_METHOD
    )
}

fn rootless_alternatives() -> Vec<String> {
    vec![
        "BYPASS_METHOD = \"tls_frag\"".to_owned(),
    ]
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const INTERCEPTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct InterceptorRuntime {
    shutdown: InterceptorShutdown,
    done_rx: oneshot::Receiver<anyhow::Result<()>>,
}

async fn stop_interceptor(interceptor: Option<InterceptorRuntime>) -> anyhow::Result<()> {
    let Some(interceptor) = interceptor else {
        return Ok(());
    };

    interceptor.shutdown.request();
    let mut report_rx = spawn_interceptor_report(interceptor.done_rx);
    wait_for_interceptor_shutdown(&mut report_rx).await
}

async fn run_headless_proxy(
    proxy_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    event_rx: mpsc::UnboundedReceiver<ProxyEvent>,
    interceptor: Option<InterceptorRuntime>,
    events: RuntimeEventEmitter,
) -> anyhow::Result<()> {
    log_headless_proxy_start();
    let mut proxy_handle = proxy_handle;
    let event_log_handle = tokio::spawn(log_headless_proxy_events(event_rx, events.clone()));

    if let Some(interceptor) = interceptor {
        let shutdown = interceptor.shutdown.clone();
        let mut intercept_report_rx = spawn_interceptor_report(interceptor.done_rx);
        tokio::select! {
            signal = shutdown_signal() => {
                let reason = signal?;
                proxy_handle.abort();
                shutdown.request();
                let result = wait_for_interceptor_shutdown(&mut intercept_report_rx).await;
                if result.is_ok() {
                    events.emit(RuntimeEvent::GracefulShutdown { reason });
                }
                event_log_handle.abort();
                result
            }
            result = &mut proxy_handle => {
                shutdown.request();
                let proxy_result = result.context("proxy task panicked")?;
                let stop_result = wait_for_interceptor_shutdown(&mut intercept_report_rx).await;
                event_log_handle.abort();
                proxy_result?;
                stop_result
            }
            intercept_result = intercept_report_rx.recv() => {
                proxy_handle.abort();
                event_log_handle.abort();
                match intercept_result {
                    Some(Ok(())) => Err(anyhow::anyhow!("packet interceptor stopped unexpectedly")),
                    Some(Err(e)) => Err(e.context("packet interceptor stopped")),
                    None => Err(anyhow::anyhow!("packet interceptor thread stopped before reporting a result")),
                }
            }
        }
    } else {
        tokio::select! {
            signal = shutdown_signal() => {
                let reason = signal?;
                events.emit(RuntimeEvent::GracefulShutdown { reason });
                proxy_handle.abort();
                event_log_handle.abort();
                Ok(())
            }
            result = &mut proxy_handle => {
                event_log_handle.abort();
                result.context("proxy task panicked")?
            }
        }
    }
}

fn spawn_interceptor_report(
    done_rx: oneshot::Receiver<anyhow::Result<()>>,
) -> mpsc::UnboundedReceiver<anyhow::Result<()>> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let result = match done_rx.await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "packet interceptor thread stopped before reporting a result"
            )),
        };
        let _ = tx.send(result);
    });
    rx
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn wait_for_interceptor_shutdown(
    report_rx: &mut mpsc::UnboundedReceiver<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    match tokio::time::timeout(INTERCEPTOR_SHUTDOWN_TIMEOUT, report_rx.recv()).await {
        Ok(Some(Ok(()))) => Ok(()),
        Ok(Some(Err(e))) => Err(e.context("packet interceptor stopped during shutdown")),
        Ok(None) => Err(anyhow::anyhow!(
            "packet interceptor thread stopped before reporting a result"
        )),
        Err(_) => Err(anyhow::anyhow!(
            "packet interceptor did not stop within {} seconds",
            INTERCEPTOR_SHUTDOWN_TIMEOUT.as_secs()
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
async fn wait_for_interceptor_shutdown(
    report_rx: &mut mpsc::UnboundedReceiver<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let _ = tokio::time::timeout(Duration::from_millis(100), report_rx.recv()).await;
    Ok(())
}

async fn log_headless_proxy_events(
    mut event_rx: mpsc::UnboundedReceiver<ProxyEvent>,
    events: RuntimeEventEmitter,
) {
    while let Some(event) = event_rx.recv().await {
        match event {
            ProxyEvent::ListenerStarted { mode, listen_addr } => {
                events.emit(RuntimeEvent::ListenerStarted {
                    mode,
                    listen_addr: listen_addr.to_string(),
                });
            }
            ProxyEvent::ConnectionAccepted { peer, src_port, upstream_ip } => {
                events.emit(RuntimeEvent::ConnectionAccepted {
                    peer: peer.to_string(),
                    src_port,
                });
                info!(%peer, src_port, %upstream_ip, "accepted proxy connection");
            }
            ProxyEvent::BypassComplete { src_port, outcome } => match outcome {
                ip_bypass_plus_frag_core::flow::BypassOutcome::FakeDataAcked => {
                    events.emit(RuntimeEvent::BypassFinished {
                        src_port,
                        status: BypassStatus::Completed,
                    });
                    info!(src_port, "bypass complete; relaying");
                }
                ip_bypass_plus_frag_core::flow::BypassOutcome::UnexpectedClose => {
                    events.emit(RuntimeEvent::BypassFinished {
                        src_port,
                        status: BypassStatus::Failed,
                    });
                    warn!(src_port, "bypass failed before relay");
                }
            },
            ProxyEvent::RelayFinished {
                src_port,
                c2s_bytes,
                s2c_bytes,
                reason,
            } => match reason {
                RelayEndReason::Completed => {
                    events.emit(RuntimeEvent::RelayBytes {
                        src_port,
                        c2s_bytes,
                        s2c_bytes,
                        is_final: true,
                    });
                    info!(src_port, c2s_bytes, s2c_bytes, "relay finished");
                }
                RelayEndReason::MaxLifetime => {
                    events.emit(RuntimeEvent::RelayBytes {
                        src_port,
                        c2s_bytes,
                        s2c_bytes,
                        is_final: true,
                    });
                    info!(
                        src_port,
                        c2s_bytes, s2c_bytes, "relay rotated after max lifetime"
                    );
                }
            },
            ProxyEvent::ConnectionError { src_port, error } => {
                events.emit(RuntimeEvent::BypassFinished {
                    src_port,
                    status: BypassStatus::Failed,
                });
                warn!(src_port, %error, "proxy connection failed");
            }
            ProxyEvent::RelayProgress {
                src_port,
                c2s_bytes,
                s2c_bytes,
            } => {
                events.emit(RuntimeEvent::RelayBytes {
                    src_port,
                    c2s_bytes,
                    s2c_bytes,
                    is_final: false,
                });
            }
            ProxyEvent::IpTargetChanged { ip } => {
                events.emit(RuntimeEvent::ActiveTargetChanged {
                    target: TargetKind::Ip,
                    sni: None,
                    ip: ip.to_string(),
                    score: None,
                });
                info!(%ip, "active IP target changed");
            }
        }
    }
}

#[cfg(unix)]
fn log_headless_proxy_start() {
    info!("running without TUI; send SIGTERM to stop");
}

#[cfg(not(unix))]
fn log_headless_proxy_start() {
    info!("running without TUI; press Ctrl-C to stop");
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<String> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut hangup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;

    loop {
        tokio::select! {
            _ = interrupt.recv() => {
                warn!("received SIGINT; continuing because --no-tui is running headless; send SIGTERM to stop");
            }
            _ = terminate.recv() => {
                info!("received SIGTERM");
                return Ok("SIGTERM".to_owned());
            }
            _ = hangup.recv() => {
                warn!("received SIGHUP; continuing because --no-tui is running headless");
            }
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<String> {
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    info!("received Ctrl-C");
    Ok("ctrl_c".to_owned())
}

// ---------------------------------------------------------------------------
// IP bypass plus mode
// ---------------------------------------------------------------------------

fn ip_bypass_plus_main(
    cfg: Arc<Config>,
    _cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
    events: RuntimeEventEmitter,
    ip_list_path: PathBuf,
    scan_timeout: Duration,
) -> Result<()> {
    // (active_ip, active_score, pool_entries)
    let (active_ip, active_score, scan_entries): (IpAddr, Option<u8>, Vec<IpProbeEntry>) = if let Some(ref forced_ip) =
        cfg.SELECTED_IP
    {
        let ip: IpAddr = forced_ip
            .parse()
            .with_context(|| format!("parsing SELECTED_IP '{forced_ip}'"))?;
        let _ = require_ipv4_target(ip, "ip_bypass_plus")?;
        info!(%ip, "ip_bypass_plus: SELECTED_IP set — skipping scan");
        (ip, None, Vec::new())
    } else {
        // Parse CIDR ranges and show selection
        let ranges = ip_bypass_plus_frag_core::ip_scanner::parse_cidr_ranges(&ip_list_path);
        let selected_range = if !ranges.is_empty() && !no_tui {
            let mut terminal = tui::enter_tui()?;
            let idx = tui::run_range_selection(&mut terminal, &ranges)?;
            tui::leave_tui(terminal)?;
            Some(idx)
        } else {
            None
        };

        // Load IPs from selected range only (randomized order)
        let ips = if let Some(idx) = selected_range {
            let (ref range_str, _) = ranges[idx];
            info!(range = %range_str, "selected CIDR range");
            let selected_net: IpNet = range_str.parse()
                .with_context(|| format!("parsing CIDR range '{}'", range_str))?;
            let all_ips = load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS)
                .with_context(|| format!("loading ip_list from '{}'", ip_list_path.display()))?;
            reject_ipv6_ip_candidates(&all_ips, "ip_bypass_plus", &ip_list_path)?;
            let mut filtered: Vec<IpAddr> = all_ips.into_iter()
                .filter(|ip| selected_net.contains(ip))
                .collect();
            // Randomize order
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            filtered.shuffle(&mut rng);
            info!(total = filtered.len(), "IPs in selected range after randomize");
            filtered
        } else {
            load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS)
                .with_context(|| format!("loading ip_list from '{}'", ip_list_path.display()))?
        };

        if ips.is_empty() {
            anyhow::bail!(
                "ip_list '{}' is empty — add at least one IPv4 address or IPv4 CIDR",
                ip_list_path.display()
            );
        }

        let total_ips = ips.len();
        info!(total_ips, "ip_bypass_plus: scanning IPv4 list");

        let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
        let cfg_clone = cfg.clone();
        let entries = if no_tui {
            let entries = rt.block_on(scan_ip_list_headless(
                ips,
                scan_sni,
                scan_timeout,
                cfg_clone,
                &events,
                Some(&ip_list_path),
            ));
            log_ip_scan_results("ip_bypass_plus: headless IP scan", &entries);
            Ok(entries)
        } else {
            scan_ip_list_with_ip_progress(cfg_clone, &rt, ips, scan_sni, scan_timeout, total_ips)
        }?;

        if entries.is_empty() {
            anyhow::bail!("ip_bypass_plus: no IPs passed the scan — check connectivity or ip_list");
        }

        if no_tui && !cfg.AUTO_SELECT {
            warn!("--no-tui cannot show the mode selection; auto-selecting single IP mode");
        }

        // Ask user to choose mode (unless auto or headless)
        let use_pool = if cfg.AUTO_SELECT || no_tui {
            false
        } else {
            let mut terminal = tui::enter_tui()?;
            let choice = tui::run_mode_selection(&mut terminal)?;
            tui::leave_tui(terminal)?;
            choice
        };

        if use_pool {
            let pool_size = cfg.IP_POOL.min(entries.len());
            info!(pool_size, "ip_bypass_plus: multi-IP pool mode selected by user");
            for (i, e) in entries.iter().take(pool_size).enumerate() {
                info!(rank = i + 1, ip = %e.ip, score = e.score, "pool IP");
            }
            let first_ip = IpAddr::from(entries[0].ip);
            let first_score = entries[0].score;
            let pool_entries: Vec<IpProbeEntry> = entries.into_iter().take(pool_size).collect();
            (first_ip, Some(first_score), pool_entries)
        } else {
            let selected_entry: IpProbeEntry = if cfg.AUTO_SELECT || no_tui {
                let best = entries.into_iter().next().context("no probe results")?;
                info!(ip = %best.ip, score = best.score, "ip_bypass_plus: auto-selected IP");
                best
            } else {
                let mut terminal = tui::enter_tui()?;
                let result = tui::run_ip_selection(&mut terminal, &entries);
                tui::leave_tui(terminal)?;
                let entry = result.context("IP selection")?;
                info!(ip = %entry.ip, score = entry.score, "ip_bypass_plus: selected IP");
                entry
            };
            (IpAddr::from(selected_entry.ip), Some(selected_entry.score), Vec::new())
        }
    };
    events.emit(RuntimeEvent::SelectedTarget {
        target: TargetKind::Ip,
        sni: None,
        ip: active_ip.to_string(),
        score: active_score,
    });

    let active_v4 = require_ipv4_target(active_ip, "ip_bypass_plus")?;
    let interface_ip = default_interface_ipv4(active_v4)
        .context("could not determine local interface IP for upstream")?;

    let active_ip_arc = Arc::new(std::sync::RwLock::new(active_ip));
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ProxyEvent>();

    // Create IP pool if multi-IP mode (user selected "use multi ip" → scan_entries is non-empty)
    let ip_pool: Option<Arc<IpPool>> = if !scan_entries.is_empty() {
        let pool_entries: Vec<IpPoolEntry> = scan_entries
            .iter()
            .map(|e| IpPoolEntry { ip: IpAddr::from(e.ip), score: e.score })
            .collect();
        Some(Arc::new(IpPool::new(pool_entries)))
    } else {
        None
    };

    if cfg.RESCAN_INTERVAL_SECS > 0 {
        let rescan_cfg = cfg.clone();
        let rescan_path = ip_list_path.clone();
        let interval = cfg.RESCAN_INTERVAL_SECS;
        let active_clone = active_ip_arc.clone();
        let rescan_event_tx = if no_tui && !events.enabled() {
            None
        } else {
            Some(event_tx.clone())
        };
        rt.spawn(async move {
            background_ip_rescan(
                rescan_cfg,
                rescan_path,
                interval,
                active_clone,
                rescan_event_tx,
                no_tui,
            )
            .await;
        });
    }

    info!(
        %active_v4,
        %interface_ip,
        method = %cfg.BYPASS_METHOD,
        "ip_bypass_plus: starting proxy"
    );

    let flows = new_flow_table();
    let interceptor_runtime = if cfg.BYPASS_METHOD == "tls_frag" {
        info!("ip_bypass_plus: tls_frag selected; skipping packet interceptor");
        None
    } else {
        let method_box = build_method(&cfg)
            .with_context(|| format!("unknown BYPASS_METHOD '{}'", cfg.BYPASS_METHOD))?;
        let method: Arc<dyn ip_bypass_plus_frag_core::methods::BypassMethod> = Arc::from(method_box);

        let filter = FilterSpec {
            interface_ip,
            remote_ip: None,
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
        };
        let interceptor = DefaultInterceptor::open(filter).context("open packet interceptor")?;

        let handler = Handler::new(flows.clone(), method);
        let (intercept_done_tx, intercept_done_rx) = oneshot::channel();
        let shutdown = InterceptorShutdown::default();
        let thread_shutdown = shutdown.clone();
        std::thread::Builder::new()
            .name("ip-bypass-plus-intercept".into())
            .spawn(move || {
                let result = interceptor.run_until(handler, thread_shutdown);
                if let Err(ref e) = result {
                    error!(error = %e, "intercept loop ended with error");
                }
                let _ = intercept_done_tx.send(result);
            })
            .context("spawn intercept thread")?;
        Some(InterceptorRuntime {
            shutdown,
            done_rx: intercept_done_rx,
        })
    };

    let cfg_dash = cfg.clone();

    let dashboard_event_tx = Some(event_tx.clone());
    let proxy_active = active_ip_arc.clone();
    let proxy_pool = ip_pool.clone();
    let proxy_handle = rt.spawn(async move {
        run_ip_bypass_plus_proxy(cfg, proxy_active, interface_ip, flows, dashboard_event_tx, proxy_pool).await
    });

    if no_tui {
        let result = rt.block_on(run_headless_proxy(
            proxy_handle,
            event_rx,
            interceptor_runtime,
            events.clone(),
        ));
        info!("shutting down");
        return result;
    }

    let dash_info = if let Some(ref pool) = ip_pool {
        tui::DashboardInfo::IpBypassPlusFragPool { active_ip, pool: pool.entries().to_vec() }
    } else {
        tui::DashboardInfo::IpBypassPlusFrag { ip: active_ip }
    };
    let mut terminal = tui::enter_tui()?;
    let dash_result = tui::run_dashboard(&mut terminal, &mut event_rx, &dash_info, &cfg_dash);
    tui::leave_tui(terminal)?;

    proxy_handle.abort();
    rt.block_on(stop_interceptor(interceptor_runtime))?;
    info!("shutting down");
    dash_result?;

    Ok(())
}

fn require_ipv4_target(ip: IpAddr, mode: &str) -> anyhow::Result<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => anyhow::bail!("{mode} is IPv4-only; got IPv6 address"),
    }
}

fn reject_ipv6_ip_candidates(ips: &[IpAddr], mode: &str, path: &Path) -> anyhow::Result<()> {
    for ip in ips {
        if ip.is_ipv6() {
            anyhow::bail!("{mode} is IPv4-only; found IPv6 address {} in {}", ip, path.display());
        }
    }
    Ok(())
}

async fn background_ip_rescan(
    cfg: Arc<Config>,
    path: PathBuf,
    interval_secs: u64,
    active_ip: Arc<std::sync::RwLock<IpAddr>>,
    event_tx: Option<ProxyEventSender>,
    headless: bool,
) {
    let interval = Duration::from_secs(interval_secs);
    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
    loop {
        tokio::time::sleep(interval).await;
        if headless {
            info!(path = %path.display(), "background IP rescan starting");
        } else {
            debug!("background IP rescan starting");
        }
        let ips = match load_ip_list(&path, cfg.IPV6_MAX_HOSTS) {
            Ok(ips) => ips,
            Err(e) => {
                warn!(error = %e, "background IP rescan: failed to load ip_list");
                continue;
            }
        };
        let cfg_clone = cfg.clone();
        let sni_clone = scan_sni.clone();
        let entries = scan_ip_list(ips, sni_clone, scan_timeout, cfg_clone, None).await;

        if headless {
            info!(
                "background IP rescan complete — {} IPs",
                entries.len()
            );
            for (rank, e) in entries.iter().take(5).enumerate() {
                info!(rank = rank + 1, "{}", e.summary_line());
            }
        } else {
            debug!(
                "background IP rescan complete — {} IPs",
                entries.len()
            );
        }

        if let Some(best) = entries.first() {
            let current = *active_ip.read().unwrap();
            if current != best.ip && best.score >= cfg.SNI_SWITCH_MIN_SCORE {
                *active_ip.write().unwrap() = best.ip;
                info!(
                    old_ip = %current,
                    new_ip = %best.ip,
                    score = best.score,
                    "hot-swapped active IP target"
                );
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(ProxyEvent::IpTargetChanged { ip: best.ip });
                }
            }
        }
    }
}

fn log_ip_scan_results(context: &str, entries: &[IpProbeEntry]) {
    info!("{context} complete — {} IPs probed", entries.len());
    for e in entries {
        info!("{}", e.summary_line());
    }
}

async fn scan_ip_list_headless(
    ips: Vec<IpAddr>,
    scan_sni: Arc<str>,
    timeout: Duration,
    cfg: Arc<Config>,
    events: &RuntimeEventEmitter,
    path: Option<&Path>,
) -> Vec<IpProbeEntry> {
    let total = ips.len();
    events.emit(RuntimeEvent::ScanStarted {
        scan: ScanKind::Ip,
        path: path.map(|p| p.display().to_string()),
        total: Some(total),
    });

    if !events.enabled() {
        let entries = scan_ip_list(ips, scan_sni, timeout, cfg, None).await;
        events.emit(RuntimeEvent::ScanCompleted {
            scan: ScanKind::Ip,
            results: entries.len(),
        });
        return entries;
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<IpScanEvent>();
    let progress_events = events.clone();
    let progress_handle = tokio::spawn(async move {
        let mut probe_completed = 0usize;
        while let Some(event) = rx.recv().await {
            match event {
                IpScanEvent::TcpDone { tcp_tested } => {
                    progress_events.emit(RuntimeEvent::ScanProgress {
                        scan: ScanKind::Ip,
                        phase: Some("tcp".to_owned()),
                        completed: tcp_tested,
                        total: Some(total),
                        sni: None,
                        ip: None,
                        score: None,
                    });
                }
                IpScanEvent::ProbeComplete(entry) => {
                    probe_completed += 1;
                    progress_events.emit(RuntimeEvent::ScanProgress {
                        scan: ScanKind::Ip,
                        phase: Some("probe".to_owned()),
                        completed: probe_completed,
                        total: Some(total),
                        sni: None,
                        ip: Some(entry.ip.to_string()),
                        score: Some(entry.score),
                    });
                }
            }
        }
    });

    let entries = scan_ip_list(ips, scan_sni, timeout, cfg, Some(tx)).await;
    let _ = progress_handle.await;
    events.emit(RuntimeEvent::ScanCompleted {
        scan: ScanKind::Ip,
        results: entries.len(),
    });
    entries
}

fn scan_ip_list_with_ip_progress(
    cfg: Arc<Config>,
    rt: &tokio::runtime::Runtime,
    ips: Vec<IpAddr>,
    scan_sni: Arc<str>,
    timeout: Duration,
    total_ips: usize,
) -> anyhow::Result<Vec<IpProbeEntry>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<IpScanEvent>();
    let cfg_clone = cfg.clone();
    let scan_handle = rt.spawn(async move { scan_ip_list(ips, scan_sni, timeout, cfg_clone, Some(tx)).await });

    let mut terminal = tui::enter_tui()?;
    let (arrived, aborted) = tui::run_ip_scan_progress(&mut terminal, &mut rx, total_ips)?;
    tui::leave_tui(terminal)?;

    let sorted = if scan_handle.is_finished() {
        rt.block_on(scan_handle).context("scanner task panicked")?
    } else {
        scan_handle.abort();
        if aborted {
            info!(
                "scan aborted by user — using {} results collected so far",
                arrived.len()
            );
        }
        let mut entries = arrived;
        entries.sort_by(|a, b| {
            b.score.cmp(&a.score).then(
                a.tcp_latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
            )
        });
        entries
    };

    info!("scan complete — {} IPs probed", sorted.len());
    for e in &sorted {
        info!("{}", e.summary_line());
    }
    Ok(sorted)
}


