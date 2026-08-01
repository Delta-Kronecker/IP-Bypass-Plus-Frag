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
use ip_bypass_plus_frag_core::proxy::{run_ip_bypass_plus_proxy, CONNECT_PORT};
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
    log::set_max_level(log::level_filters::LevelFilter::Trace);
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
/// as a string and the target IP directly.
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

    // Scan to find interface IP
    let scan_rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let interface_ip = match scan_rt.block_on(async {
        let probe_ip = std::net::IpAddr::V4(target_addr);
        let ips = vec![probe_ip];
        let _entries =
            scan_ip_list(ips.clone(), scan_sni, timeout, cfg.clone(), None).await;
        // Use default interface discovery
        default_interface_ipv4(target_addr).ok()
    }) {
        Some(ip) => ip,
        None => {
            emit_log(1, "failed to determine interface IP");
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
    rt.spawn(async move {
        let _ = run_ip_bypass_plus_proxy(
            proxy_cfg,
            active_ip,
            interface_ip,
            flows,
            None,
            None,
        )
        .await;
    });

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
