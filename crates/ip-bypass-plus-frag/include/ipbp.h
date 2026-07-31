/**
 * IP Bypass Plus Frag — C FFI API
 *
 * Use this header to integrate the library into Android apps (e.g. v2rayNG).
 * Load the .so with System.loadLibrary("ip_bypass_plus_frag") or dlopen().
 *
 * Example JNI usage from Kotlin:
 *   System.loadLibrary("ip_bypass_plus_frag")
 *   val handle = ipbp_start_proxy_from_config(configText, targetIp)
 *   // ... use handle ...
 *   ipbp_stop_proxy(handle)
 */

#ifndef IPBP_H
#define IPBP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Log callback: level 0=info, 1=error, 2=warn. */
typedef void (*ipbp_log_callback_t)(int32_t level, const char* message);

/** Set log callback. Call before any other function. */
void ipbp_set_log_callback(ipbp_log_callback_t callback);

/** Get library version. Caller must free with ipbp_free_string(). */
char* ipbp_version(void);

/** Free a string returned by this library. */
void ipbp_free_string(char* ptr);

/**
 * Load and validate a config file.
 * Returns 0 on success, negative on error.
 */
int32_t ipbp_load_config(const char* config_path);

/**
 * Scan result entry.
 */
typedef struct {
    uint8_t ip[16];         /** IP address as string bytes */
    uint32_t ip_len;        /** Length of IP string */
    uint64_t tcp_latency_ms;
    int32_t tls_ok;
    uint64_t tls_latency_ms;
    uint64_t ttfb_ms;
    double download_bps;
    double upload_bps;
    uint8_t score;
} ScanResult;

/**
 * Scan IP list.
 * Returns number of results written, or negative on error.
 */
int32_t ipbp_scan_ips(
    const char* ip_list_path,
    const char* sni,
    uint64_t timeout_secs,
    uint32_t max_results,
    ScanResult* results_out,
    uint32_t max_ip_scan
);

/** Opaque proxy handle. */
typedef struct ProxyHandle ProxyHandle;

/**
 * Start proxy from config file path.
 * Returns handle on success, NULL on error.
 */
ProxyHandle* ipbp_start_proxy(
    const char* config_path,
    const char* target_ip,
    const char* interface_ip
);

/**
 * Start proxy from config text (no file needed).
 * This is the recommended API for Android embedding.
 * Returns handle on success, NULL on error.
 */
ProxyHandle* ipbp_start_proxy_from_config(
    const char* config_text,
    const char* target_ip
);

/**
 * Stop proxy and free handle. Handle is consumed.
 */
void ipbp_stop_proxy(ProxyHandle* handle);

#ifdef __cplusplus
}
#endif

#endif /* IPBP_H */
