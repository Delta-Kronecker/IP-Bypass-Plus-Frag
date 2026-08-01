//! C FFI API for embedding IP Bypass Plus Frag as a library in Android apps.
//!
//! This library exposes the core functionality via C-compatible functions so
//! it can be loaded by apps like v2rayNG. All functions are `extern "C"` and
//! use C-compatible types.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use log::{Level, Log, Metadata, Record};

use ip_bypass_plus_frag_core::config::Config;
use ip_bypass_plus_frag_core::flow::new_flow_table;
use ip_bypass_plus_frag_core::handler::Handler;
use ip_bypass_plus_frag_core::interceptor::{FilterSpec, PacketInterceptor};
use ip_bypass_plus_frag_core::ip_scanner::{load_ip_list, scan_ip_list};
use ip_bypass_plus_frag_core::methods::build_method;
use ip_bypass_plus_frag_core::net::default_interface_ipv4;
use ip_bypass_plus_frag_core::proxy::{run_ip_bypass_plus_proxy, IpPool, IpPoolEntry, CONNECT_PORT};
use ip_bypass_plus_frag_platform::DefaultInterceptor;

/// Opaque handle to a running proxy instance.
pub struct ProxyHandle {
    _runtime: tokio::runtime::Handle,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Scan result entry returned to the caller.
#[repr(C)]
pub struct ScanResult {
    pub ip: [u8; 16],
    pub ip_len: u32,
    pub tcp_latency_ms: u64,
    pub tls_ok: bool,
    pub tls_latency_ms: u64,
    pub ttfb_ms: u64,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub score: u8,
}

/// Log callback type. The library calls this for every log line.
pub type LogCallback = extern "C" fn(level: i32, message: *const c_char);

static mut LOG_CALLBACK: Option<LogCallback> = None;

fn emit_log(level: i32, msg: &str) {
    unsafe {
        if let Some(cb) = LOG_CALLBACK {
            if let Ok(c_msg) = CString::new(msg) {
                cb(level, c_msg.as_ptr());
            }
        }
    }
}

/// Set the log callback. Call before any other function.
///
/// # Safety
/// `callback` must be a valid function pointer.
#[no_mangle]
pub unsafe extern "C" fn ipbp_set_log_callback(callback: LogCallback) {
    LOG_CALLBACK = Some(callback);

    // Install rustls crypto provider (ring) for TLS scanning
    let _ = rustls::crypto::ring::default_provider().install_default();

    struct IpbfLogger;

    impl Log for IpbfLogger {
        fn enabled(&self, _metadata: &Metadata) -> bool {
            true
        }

        fn log(&self, record: &Record) {
            let level = match record.level() {
                Level::Error => 1,
                Level::Warn => 2,
                Level::Info => 0,
                _ => 3,
            };
            emit_log(level, &format!("{}", record.args()));
        }

        fn flush(&self) {}
    }

    let _ = log::set_logger(Box::leak(Box::new(IpbfLogger)));
    log::set_max_level(log::LevelFilter::Trace);
}

/// Get library version string. Caller must free with `ipbp_free_string`.
///
/// # Safety
/// Returns a valid C string pointer or null on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_version() -> *mut c_char {
    match CString::new(env!("CARGO_PKG_VERSION")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
/// `ptr` must have been returned by a function from this library.
#[no_mangle]
pub unsafe extern "C" fn ipbp_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Load and validate a config file.
///
/// # Safety
/// `config_path` must be a valid null-terminated C string.
/// Returns 0 on success, negative on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_load_config(config_path: *const c_char) -> i32 {
    let path = match CStr::from_ptr(config_path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match Config::from_file(path) {
        Ok(_) => 0,
        Err(e) => {
            emit_log(1, &format!("config error: {e:#}"));
            -2
        }
    }
}

/// Scan IP list and return results.
///
/// # Safety
/// - `ip_list_path` must be a valid null-terminated C string.
/// - `sni` must be a valid null-terminated C string.
/// - `results_out` must point to a valid `ScanResult` array of `max_results` entries.
/// - Returns the number of results written, or negative on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_scan_ips(
    ip_list_path: *const c_char,
    sni: *const c_char,
    timeout_secs: u64,
    max_results: u32,
    results_out: *mut ScanResult,
    max_ip_scan: u32,
) -> i32 {
    let path_str = match CStr::from_ptr(ip_list_path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let sni_str = match CStr::from_ptr(sni).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return -3,
    };

    let path = PathBuf::from(path_str);
    let cfg_text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return -4,
    };
    let mut cfg: Config = match toml::from_str(&cfg_text) {
        Ok(c) => c,
        Err(_) => return -5,
    };
    if max_ip_scan > 0 {
        cfg.MAX_IP_SCAN = max_ip_scan as usize;
    }
    let cfg = Arc::new(cfg);

    let ips = match load_ip_list(&path, cfg.IPV6_MAX_HOSTS) {
        Ok(ips) => ips,
        Err(_) => return -6,
    };
    if ips.is_empty() {
        return -7;
    }

    let scan_sni: Arc<str> = Arc::from(sni_str);
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let entries = rt.block_on(scan_ip_list(ips, scan_sni, timeout, cfg, None));

    let count = (entries.len() as u32).min(max_results);
    for (i, entry) in entries.iter().take(count as usize).enumerate() {
        let out = &mut *results_out.add(i as usize);
        let ip_str = entry.ip.to_string();
        let ip_bytes = ip_str.as_bytes();
        let copy_len = ip_bytes.len().min(15);
        out.ip[..copy_len].copy_from_slice(&ip_bytes[..copy_len]);
        out.ip[copy_len..].fill(0);
        out.ip_len = copy_len as u32;
        out.tcp_latency_ms = entry.tcp_latency_ms.unwrap_or(0);
        out.tls_ok = entry.tls_ok;
        out.tls_latency_ms = entry.tls_latency_ms.unwrap_or(0);
        out.ttfb_ms = entry.ttfb_ms.unwrap_or(0);
        out.download_bps = entry.download_bps.unwrap_or(0.0);
        out.upload_bps = entry.upload_bps.unwrap_or(0.0);
        out.score = entry.score;
    }

    count as i32
}

/// Start the proxy in the background.
///
/// # Safety
/// - `config_path` must be a valid null-terminated C string.
/// - `target_ip` must be a valid null-terminated C string (IPv4 address).
/// - `interface_ip` must be a valid null-terminated C string (IPv4 address).
/// - Returns an opaque handle on success, null on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_start_proxy(
    config_path: *const c_char,
    target_ip: *const c_char,
    interface_ip: *const c_char,
) -> *mut ProxyHandle {
    let cfg_path = match CStr::from_ptr(config_path).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let target = match CStr::from_ptr(target_ip).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let iface = match CStr::from_ptr(interface_ip).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let target_addr: std::net::Ipv4Addr = match target.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };
    let iface_addr: std::net::Ipv4Addr = match iface.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let cfg = match Config::from_file(cfg_path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            emit_log(1, &format!("config error: {e:#}"));
            return std::ptr::null_mut();
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ipbp-proxy")
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let flows = new_flow_table();
    let active_ip = Arc::new(RwLock::new(std::net::IpAddr::V4(target_addr)));

    // Start interceptor if needed
    if cfg.BYPASS_METHOD != "tls_frag" {
        let method = match build_method(&cfg) {
            Some(m) => Arc::from(m),
            None => {
                emit_log(1, &format!("unknown bypass method: {}", cfg.BYPASS_METHOD));
                return std::ptr::null_mut();
            }
        };
        let filter = FilterSpec {
            interface_ip: iface_addr,
            remote_ip: None,
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
        };
        let interceptor = match DefaultInterceptor::open(filter) {
            Ok(i) => i,
            Err(e) => {
                emit_log(1, &format!("interceptor open failed: {e:#}"));
                return std::ptr::null_mut();
            }
        };
        let handler = Handler::new(flows.clone(), method);
        std::thread::Builder::new()
            .name("ipbp-intercept".into())
            .spawn(move || {
                let _ = interceptor.run_until(handler, Default::default());
            })
            .ok();
    }

    let proxy_cfg = cfg.clone();
    rt.spawn(async move {
        let _ = run_ip_bypass_plus_proxy(
            proxy_cfg,
            active_ip,
            iface_addr,
            flows,
            None,
            None,
        )
        .await;
    });

    // Keep the runtime alive until shutdown
    let runtime_handle = rt.handle().clone();
    std::thread::Builder::new()
        .name("ipbp-keepalive".into())
        .spawn(move || {
            rt.block_on(async move {
                let _ = shutdown_rx.await;
            });
        })
        .ok();

    Box::into_raw(Box::new(ProxyHandle {
        _runtime: runtime_handle,
        shutdown_tx: Some(shutdown_tx),
    }))
}

/// Stop a running proxy and free the handle.
///
/// # Safety
/// `handle` must have been returned by `ipbp_start_proxy`.
/// The handle is consumed and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn ipbp_stop_proxy(handle: *mut ProxyHandle) {
    if handle.is_null() {
        return;
    }
    let h = Box::from_raw(handle);
    if let Some(tx) = h.shutdown_tx {
        let _ = tx.send(());
    }
}

/// Start the proxy with full config text and target IP (no file path needed).
///
/// This is the most convenient API for Android embedding: pass config contents
/// as a string and the target IP directly. Scans the full IP list, builds
/// a pool, and starts the proxy with round-robin IP rotation.
///
/// # Safety
/// - `config_text` must be a valid null-terminated C string (TOML config).
/// - `target_ip` must be a valid null-terminated C string (IPv4 address).
/// - Returns an opaque handle on success, null on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_start_proxy_from_config(
    config_text: *const c_char,
    target_ip: *const c_char,
) -> *mut ProxyHandle {
    let cfg_str = match CStr::from_ptr(config_text).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let target = match CStr::from_ptr(target_ip).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let cfg: Config = match toml::from_str(cfg_str) {
        Ok(c) => c,
        Err(e) => {
            emit_log(1, &format!("config parse error: {e:#}"));
            return std::ptr::null_mut();
        }
    };
    let cfg = Arc::new(cfg);

    let target_addr: std::net::Ipv4Addr = match target.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
    let timeout = std::time::Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);

    // Load IP list from config (absolute path)
    let ip_list_path = std::path::PathBuf::from(&cfg.IP_LIST);
    let ips = match load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS) {
        Ok(ips) => ips,
        Err(e) => {
            emit_log(1, &format!("failed to load IP list: {e:#}"));
            return std::ptr::null_mut();
        }
    };

    if ips.is_empty() {
        emit_log(1, "IP list is empty — add at least one IPv4 CIDR");
        return std::ptr::null_mut();
    }

    let total_ips = ips.len();
    emit_log(0, &format!("scanning {total_ips} IPs from {}", ip_list_path.display()));

    // Scan all IPs concurrently
    let scan_rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let cfg_clone = cfg.clone();
    let sni_clone = scan_sni.clone();
    let entries = scan_rt.block_on(scan_ip_list(ips, sni_clone, timeout, cfg_clone, None));

    if entries.is_empty() {
        emit_log(1, "no IPs passed the scan — check connectivity or ip_list");
        return std::ptr::null_mut();
    }

    // Log scan results in concise format: "104.16.0.174 tcp=91ms tls=99ms score=60"
    for e in &entries {
        let tcp_str = e.tcp_latency_ms
            .map(|v| format!("{v}ms"))
            .unwrap_or_else(|| "fail".into());
        let tls_str = if e.tls_ok {
            e.tls_latency_ms
                .map(|v| format!("{v}ms"))
                .unwrap_or_else(|| "ok".into())
        } else {
            "fail".into()
        };
        emit_log(0, &format!("{} tcp={tcp_str} tls={tls_str} score={}", e.ip, e.score));
    }

    // Auto-select the best IP (highest score, lowest latency)
    let best = &entries[0];
    let active_ip_addr: std::net::IpAddr = best.ip;
    emit_log(0, &format!("selected {} score={} — starting proxy", best.ip, best.score));

    // Determine interface IP
    let interface_ip = match default_interface_ipv4(target_addr) {
        Ok(ip) => ip,
        Err(e) => {
            emit_log(1, &format!("failed to determine interface IP: {e:#}"));
            return std::ptr::null_mut();
        }
    };

    // Build IP pool from scan results
    let pool_size = cfg.IP_POOL.min(entries.len());
    let pool_entries: Vec<IpPoolEntry> = entries.iter()
        .take(pool_size)
        .map(|e| IpPoolEntry { ip: e.ip, score: e.score })
        .collect();
    let ip_pool = if pool_entries.len() > 1 {
        emit_log(0, &format!("IP pool: {} IPs", pool_entries.len()));
        Some(Arc::new(IpPool::new(pool_entries)))
    } else {
        None
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ipbp-proxy")
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let flows = new_flow_table();
    let active_ip = Arc::new(RwLock::new(active_ip_addr));

    // Start interceptor if needed
    if cfg.BYPASS_METHOD != "tls_frag" {
        let method = match build_method(&cfg) {
            Some(m) => Arc::from(m),
            None => {
                emit_log(1, &format!("unknown bypass method: {}", cfg.BYPASS_METHOD));
                return std::ptr::null_mut();
            }
        };
        let filter = FilterSpec {
            interface_ip,
            remote_ip: None,
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
        };
        let interceptor = match DefaultInterceptor::open(filter) {
            Ok(i) => i,
            Err(e) => {
                emit_log(1, &format!("interceptor open failed: {e:#}"));
                return std::ptr::null_mut();
            }
        };
        let handler = Handler::new(flows.clone(), method);
        std::thread::Builder::new()
            .name("ipbp-intercept".into())
            .spawn(move || {
                let _ = interceptor.run_until(handler, Default::default());
            })
            .ok();
    }

    let proxy_cfg = cfg.clone();
    let proxy_pool = ip_pool.clone();
    rt.spawn(async move {
        let _ = run_ip_bypass_plus_proxy(
            proxy_cfg,
            active_ip.clone(),
            interface_ip,
            flows,
            None,
            proxy_pool,
        )
        .await;
    });

    // Background rescan if configured
    if cfg.RESCAN_INTERVAL_SECS > 0 {
        let rescan_cfg = cfg.clone();
        let rescan_path = ip_list_path;
        let interval = cfg.RESCAN_INTERVAL_SECS;
        let active_clone = active_ip.clone();
        rt.spawn(async move {
            background_ip_rescan(rescan_cfg, rescan_path, interval, active_clone).await;
        });
    }

    let runtime_handle = rt.handle().clone();
    std::thread::Builder::new()
        .name("ipbp-keepalive".into())
        .spawn(move || {
            rt.block_on(async move {
                let _ = shutdown_rx.await;
            });
        })
        .ok();

    Box::into_raw(Box::new(ProxyHandle {
        _runtime: runtime_handle,
        shutdown_tx: Some(shutdown_tx),
    }))
}

/// Background IP rescan — periodically re-scans the IP list and hot-swaps the active target.
async fn background_ip_rescan(
    cfg: Arc<Config>,
    path: std::path::PathBuf,
    interval_secs: u64,
    active_ip: Arc<RwLock<std::net::IpAddr>>,
) {
    let interval = std::time::Duration::from_secs(interval_secs);
    let scan_timeout = std::time::Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
    loop {
        tokio::time::sleep(interval).await;
        emit_log(0, &format!("background IP rescan starting (every {}s)", interval_secs));
        let ips = match load_ip_list(&path, cfg.IPV6_MAX_HOSTS) {
            Ok(ips) => ips,
            Err(e) => {
                emit_log(1, &format!("background rescan: failed to load IP list: {e:#}"));
                continue;
            }
        };
        let cfg_clone = cfg.clone();
        let sni_clone = scan_sni.clone();
        let entries = scan_ip_list(ips, sni_clone, scan_timeout, cfg_clone, None).await;

        if let Some(best) = entries.first() {
            let current = *active_ip.read().unwrap();
            if current != best.ip && best.score >= cfg.SNI_SWITCH_MIN_SCORE {
                *active_ip.write().unwrap() = best.ip;
                emit_log(0, &format!(
                    "hot-swapped active IP: {} -> {} (score={})",
                    current, best.ip, best.score
                ));
            }
        }
    }
}
