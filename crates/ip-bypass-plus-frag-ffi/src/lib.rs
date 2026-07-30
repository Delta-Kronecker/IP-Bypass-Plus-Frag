//! C FFI bindings for IP Bypass Plus Frag.
//!
//! Provides a minimal C API for embedding the proxy core into Android apps
//! or other native environments. The library runs the proxy on a background
//! thread and exposes start/stop/version functions.
//!
//! # Exported Functions
//!
//! | Function | Signature | Description |
//! |----------|-----------|-------------|
//! | `ibpf_start` | `(config_path: *const c_char) -> c_int` | Start proxy with config file |
//! | `ibpf_stop` | `() -> ()` | Stop the running proxy |
//! | `ibpf_is_running` | `() -> bool` | Check if proxy is active |
//! | `ibpf_version` | `() -> *const c_char` | Get library version string |

use std::ffi::{c_char, CStr, CString};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;

static RUNNING: AtomicBool = AtomicBool::new(false);
static PROXY_ABORT: OnceLock<tokio::task::AbortHandle> = OnceLock::new();
static INTERCEPTOR_SHUTDOWN: OnceLock<ip_bypass_plus_frag_core::interceptor::InterceptorShutdown> =
    OnceLock::new();

/// Start the IP Bypass Plus Frag proxy.
///
/// # Arguments
/// * `config_path` — Null-terminated path to `config.toml`.
///
/// # Returns
/// * `0` — Success.
/// * `-1` — Already running.
/// * `-2` — Invalid config path (not valid UTF-8).
/// * `-3` — Failed to spawn background thread.
///
/// # Safety
/// `config_path` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn ibpf_start(config_path: *const c_char) -> c_int {
    if RUNNING.load(Ordering::SeqCst) {
        return -1;
    }

    let path = match unsafe { CStr::from_ptr(config_path) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -2,
    };

    RUNNING.store(true, Ordering::SeqCst);

    match thread::Builder::new()
        .name("ibpf-main".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("ibpf: failed to create tokio runtime: {e}");
                    RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
            };

            rt.block_on(async {
                if let Err(e) = run_headless(&path).await {
                    eprintln!("ibpf: proxy error: {e:#}");
                }
            });

            RUNNING.store(false, Ordering::SeqCst);
        }) {
        Ok(_) => 0,
        Err(_) => {
            RUNNING.store(false, Ordering::SeqCst);
            -3
        }
    }
}

/// Stop the running proxy.
///
/// Signals the interceptor to shut down and aborts the proxy task.
/// Active connections will be dropped.
#[no_mangle]
pub extern "C" fn ibpf_stop() {
    RUNNING.store(false, Ordering::SeqCst);

    if let Some(shutdown) = INTERCEPTOR_SHUTDOWN.get() {
        shutdown.request();
    }

    if let Some(abort) = PROXY_ABORT.get() {
        abort.abort();
    }
}

/// Check whether the proxy is currently running.
#[no_mangle]
pub extern "C" fn ibpf_is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Get the library version as a null-terminated C string.
///
/// The returned pointer is valid for the lifetime of the process.
/// Do **not** free or mutate it.
#[no_mangle]
pub extern "C" fn ibpf_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    let v = VERSION.get_or_init(|| CString::new(env!("CARGO_PKG_VERSION")).unwrap());
    v.as_ptr()
}

// ---------------------------------------------------------------------------
// Internal: headless proxy runner (no TUI, no interactive prompts)
// ---------------------------------------------------------------------------

async fn run_headless(config_path: &str) -> anyhow::Result<()> {
    use ip_bypass_plus_frag_core::config::Config;
    use ip_bypass_plus_frag_core::flow::new_flow_table;
    use ip_bypass_plus_frag_core::ip_scanner::{load_ip_list, scan_ip_list};
    use ip_bypass_plus_frag_core::interceptor::{FilterSpec, PacketInterceptor};
    use ip_bypass_plus_frag_core::methods::build_method;
    use ip_bypass_plus_frag_core::net::default_interface_ipv4;
    use ip_bypass_plus_frag_core::proxy::run_ip_bypass_plus_proxy;
    use ip_bypass_plus_frag_platform::DefaultInterceptor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    // Install rustls crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialize tracing (logs to stderr)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();

    let cfg = Config::from_file(config_path)?;
    let cfg = Arc::new(cfg);

    // Determine target IP
    let active_ip: IpAddr = if let Some(ref ip_str) = cfg.SELECTED_IP {
        ip_str.parse()?
    } else {
        let ip_list_path = std::path::PathBuf::from(&cfg.IP_LIST);
        let ips = load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS)?;
        if ips.is_empty() {
            anyhow::bail!("ip_list is empty — add at least one IPv4 CIDR");
        }
        let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
        let timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
        let entries = scan_ip_list(ips, scan_sni, timeout, cfg.clone(), None, Some(1000)).await;
        entries
            .first()
            .map(|e| e.ip)
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    };

    let active_v4 = match active_ip {
        IpAddr::V4(v4) => v4,
        _ => anyhow::bail!("ip_bypass_plus is IPv4-only"),
    };

    let interface_ip = default_interface_ipv4(active_v4)?;
    let active_ip_arc = Arc::new(std::sync::RwLock::new(active_ip));
    let flows = new_flow_table();

    // Start packet interceptor (for tls_record_frag method)
    if cfg.BYPASS_METHOD != "tls_frag" {
        use ip_bypass_plus_frag_core::handler::Handler;

        let method = build_method(&cfg)
            .ok_or_else(|| anyhow::anyhow!("unknown BYPASS_METHOD: {}", cfg.BYPASS_METHOD))?;
        let method: Arc<dyn ip_bypass_plus_frag_core::methods::BypassMethod> = Arc::from(method);

        let filter = FilterSpec {
            interface_ip,
            remote_ip: None,
            remote_port: 443,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
        };

        let interceptor = DefaultInterceptor::open(filter)?;
        let handler = Handler::new(flows.clone(), method);
        let shutdown = ip_bypass_plus_frag_core::interceptor::InterceptorShutdown::default();

        INTERCEPTOR_SHUTDOWN.set(shutdown.clone()).ok();

        thread::Builder::new()
            .name("ibpf-intercept".into())
            .spawn(move || {
                if let Err(e) = interceptor.run_until(handler, shutdown) {
                    eprintln!("ibpf: interceptor error: {e}");
                }
            })?;
    }

    // Start proxy (this runs until aborted)
    let proxy_handle = tokio::spawn(async move {
        let _ = run_ip_bypass_plus_proxy(
            cfg,
            active_ip_arc,
            interface_ip,
            flows,
            None, // no event sender
            None, // no IP pool
        )
        .await;
    });

    PROXY_ABORT.set(proxy_handle.abort_handle()).ok();

    // Wait for proxy to finish (or be aborted)
    let _ = proxy_handle.await;

    tracing::info!("ibpf: proxy stopped");
    Ok(())
}
