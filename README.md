# IpBypassPlusFrag

> **IPv4 DPI bypass proxy with real-SNI-preserving fragmentation** — built from [ZeroDPI](https://github.com/mhdr/ZeroDPI)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20android%20%7C%20termux-blue)

---

## What is IpBypassPlusFrag?

IpBypassPlusFrag is a **stripped-down, focused fork** of ZeroDPI that only supports the `ip_bypass_plus` mode. It scans IPv4 addresses, selects the best candidates, and relays VPN traffic through them while applying DPI bypass methods that preserve the VPN client's real SNI.

### How it was built from ZeroDPI

This project was extracted from ZeroDPI by:

1. **Removing all non-ip_bypass_plus modes** — `sni_spoof`, `ip_bypass`, `sni_scan`, `ip_scan`, `proxy_scan` were all removed
2. **Removing non-supported bypass methods** — Only `tls_record_frag` and `tls_frag` remain (the two methods that preserve the real SNI)
3. **Removing SNI-related modules** — `sni_scanner`, `tls_template`, `proxy_tester` were removed since they're only needed for SNI spoofing
4. **Removing all wrong_* bypass methods** — `wrong_seq`, `wrong_checksum`, `wrong_md5`, `wrong_ack`, `wrong_timestamp` and their variants were removed
5. **Simplifying config** — Only `ip_bypass_plus`-relevant config fields remain
6. **Adding multi-IP pool** — Round-robin IP selection with `IP_POOL` parameter
7. **Adding CIDR range selection** — Interactive range picker at startup
8. **Adding `MAX_IP_SCAN`** — Stop scanning after finding N healthy IPs
9. **Custom scoring formula** — Speed-focused scoring (upload > download > latency)
10. **Custom dashboard** — IP stats table showing per-IP connection counts and bytes

All bypass method implementations (`tls_record_frag`, `tcp_segmentation`), the IP scanner, proxy relay, flow tracking, handler state machine, and platform backends (NFQUEUE/WinDivert) are **original ZeroDPI code**, unchanged.

---

## Features

| Feature | Description |
|---------|-------------|
| **2 bypass methods** | `tls_record_frag` (TLS record fragmentation via packet interception), `tls_frag` (TCP-level segmentation via socket writes) |
| **Multi-IP pool** | Round-robin connections across multiple IPs with `IP_POOL` parameter |
| **CIDR range selection** | Interactive picker to choose which IP range to scan |
| **Headless mode** | `--range`, `--pool`, `--no-tui` for non-interactive / scripted operation |
| **Smart scan stop** | `MAX_IP_SCAN` stops scanning after finding N healthy IPs |
| **Speed-focused scoring** | Upload speed weighted highest, then download, then latency |
| **IP stats dashboard** | Shows per-IP connection count, upload/download bytes |
| **TUI dashboard** | Ratatui-powered live stats |
| **JSON events** | `--json-events` for headless/Android controller integration |
| **Background rescan** | Periodic re-scanning with automatic target switching |
| **Android library** | C FFI `.so` for embedding in apps like v2rayNG |
| **Cross-platform** | Windows (WinDivert), Linux/Android (NFQUEUE), Termux (static musl) |

---

## Bypass Methods

| Method | Mechanism | Requires Packet Interception? |
|--------|-----------|:---:|
| `tls_record_frag` | Splits real ClientHello into multiple small TLS records | Yes (WinDivert/NFQUEUE) |
| `tls_frag` | Writes selected client data in small TCP chunks with TCP_NODELAY | No |

### Which method to use?

| Situation | Try |
|-----------|-----|
| Windows or Linux with root/admin | `tls_record_frag` |
| Termux or no root access | `tls_frag` |
| Need real SNI preserved | Both preserve real SNI |

---

## Configuration

### Key parameters

```toml
MODE = "ip_bypass_plus"
IP_POOL = 10                    # Number of IPs in rotation pool
MAX_IP_SCAN = 1000              # Stop after finding 1000 healthy IPs (0 = unlimited)
BYPASS_METHOD = "tls_frag"      # or "tls_record_frag"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 40443
```

### How `MAX_IP_SCAN` works

The scan continues until `MAX_IP_SCAN` IPs with **all** of these healthy criteria are found:
- TCP latency: has value
- TLS handshake: success
- Certificate: valid
- TTFB: has value
- Download speed: has value
- Upload speed: has value

If an IP is missing any of these, it's not counted as healthy.

### Scoring formula (0–100)

| Component | Max Points |
|-----------|:---:|
| Upload speed | 20 |
| Download speed | 15 |
| TCP latency | 15 |
| TLS latency | 15 |
| TTFB | 15 |
| TLS success | 5 |
| Cert valid | 5 |
| All phases bonus | 10 |

Upload speed is weighted higher than download because VPN upload performance is typically more critical.

---

## Quick Start

### Windows

```cmd
cd ip-bypass-plus-frag-windows
ip-bypass-plus-frag.exe --config config.toml
```

### Termux

```bash
tar xzf ip-bypass-plus-frag-termux.tar.gz
chmod +x ip-bypass-plus-frag
./ip-bypass-plus-frag --config config.toml
```

### Android (embedding in apps)

The Android release provides a `.so` shared library with a C FFI API for embedding in apps like v2rayNG.

```bash
tar xzf ip-bypass-plus-frag-android-aarch64.tar.gz
```

#### C API (`ipbp.h`)

```c
// Get library version (free with ipbp_free_string)
char *ipbp_version(void);

// Load config from file path. Returns 0 on success.
int ipbp_load_config(const char *config_path);

// Start proxy with config text + target IP. Returns opaque handle.
void *ipbp_start_proxy_from_config(const char *config_text, const char *target_ip);

// Stop proxy and free handle.
void ipbp_stop_proxy(void *handle);

// Set log callback (call before any other function).
typedef void (*LogCallback)(int level, const char *message);
void ipbp_set_log_callback(LogCallback callback);
```

#### Example (JNI / Android)

```c
#include "ipbp.h"

// Set up logging
ipbp_set_log_callback(my_log_fn);

// Start proxy
void *handle = ipbp_start_proxy_from_config(config_toml_str, "104.16.0.1");
if (handle) {
    // ... proxy is running ...
    ipbp_stop_proxy(handle);
}
```

### First run flow

1. **Select CIDR range** (if multiple ranges in `ip_list.txt`)
2. **Select mode** — `select 1 ip` or `use multi ip`
3. **Select IP** (if single mode)
4. **Dashboard** — IP stats with connection counts

---

## ip_list.txt format

```
104.16.0.0/16
104.17.0.0/16
```

---

## CLI Options

```
ip-bypass-plus-frag [OPTIONS]

Options:
  -c, --config <PATH>              Path to config.toml
      --listen-host <HOST>         Override LISTEN_HOST
      --listen-port <PORT>         Override LISTEN_PORT
      --auto-select                Auto-select top-ranked candidate
      --no-tui                     Disable terminal UI (headless mode)
      --json-events                Emit JSON events to stdout
      --method <METHOD>            Override BYPASS_METHOD
      --queue-num <NUM>            Override NFQUEUE queue number
      --scan-timeout <SECS>        Override SCAN_TIMEOUT_SECS
      --rescan-interval <SECS>     Override RESCAN_INTERVAL_SECS
      --sni-switch-min-score <N>   Override SNI_SWITCH_MIN_SCORE
      --bypass-timeout <SECS>      Override BYPASS_TIMEOUT_SECS
      --relay-max-lifetime <SECS>  Override RELAY_MAX_LIFETIME_SECS
      --range <CIDR>               Skip range selection, use this CIDR (e.g. 104.16.0.0/16)
      --pool                       Skip mode selection, use multi-IP pool mode
```

### Headless / Non-interactive usage

For scripted or Android embedding, skip all TUI prompts:

```bash
# Fully headless: select range + pool mode automatically
ip-bypass-plus-frag --no-tui --range 104.16.0.0/16 --pool -c config.toml

# JSON events for controller integration
ip-bypass-plus-frag --no-tui --json-events --range 104.16.0.0/16 --pool -c config.toml
```

---

## Building from Source

### Prerequisites

- Rust toolchain (stable)
- For Windows builds: `x86_64-pc-windows-gnu` target + mingw-w64
- For Android builds: Android NDK r26b
- For Termux builds: `cross` (`cargo install cross --git https://github.com/cross-rs/cross`)

### Build commands

```bash
# Windows (on Linux, cross-compile)
cargo build --release --target x86_64-pc-windows-gnu

# Android shared library (for app embedding)
cargo build --release --target aarch64-linux-android --lib --no-default-features

# Termux static binary (uses cross + Docker)
cross build --release --target aarch64-unknown-linux-musl
```

---

## Project Structure

```
IP-Bypass-Plus-Frag/
├── Cargo.toml                        # Workspace root
├── config.toml                       # Configuration
├── ip_list.txt                       # IP/CIDR list
├── .cargo/config.toml                # WINDIVERT_PATH env
├── WinDivert_WinDivert64/            # WinDivert DLL + driver
├── .github/workflows/release.yml     # CI: Windows + Android + Termux builds
├── crates/
│   ├── ip-bypass-plus-frag-core/     # Core logic
│   │   └── src/
│   │       ├── config.rs             # Config parsing (ip_bypass_plus only)
│   │       ├── flow.rs               # Flow tracking (unchanged from ZeroDPI)
│   │       ├── handler.rs            # TCP state machine (unchanged)
│   │       ├── interceptor.rs        # Packet interception traits (unchanged)
│   │       ├── ip_scanner.rs         # IP scanning + scoring
│   │       ├── proxy.rs              # TCP relay + pool rotation
│   │       ├── net.rs                # Network helpers
│   │       └── methods/
│   │           ├── tls_record_frag.rs    # TLS record fragmentation
│   │           └── tcp_segmentation.rs   # TCP-level segmentation
│   ├── ip-bypass-plus-frag-platform/ # Platform backends
│   │   └── src/
│   │       ├── linux.rs              # NFQUEUE (unchanged from ZeroDPI)
│   │       └── windows.rs            # WinDivert (unchanged from ZeroDPI)
│   └── ip-bypass-plus-frag/          # CLI binary + C FFI library
│       ├── include/ipbp.h            # C header for Android embedding
│       └── src/
│           ├── main.rs               # Entry point (ip_bypass_plus only)
│           ├── lib.rs                # C FFI API (cdylib for Android)
│           ├── tui.rs                # Dashboard + selection UI
│           └── runtime_events.rs     # JSON event emitter
└── dist/                             # Release archives
    ├── windows/
    ├── android/
    └── termux/
```

---

## Credits

- Built on [ZeroDPI](https://github.com/mhdr/ZeroDPI) by ZeroDPI contributors
- DPI bypass techniques inspired by [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)
- Android cross-compilation via [Android NDK](https://developer.android.com/ndk)
- Termux cross-compilation powered by [cross](https://github.com/cross-rs/cross)

---

## License

MIT
