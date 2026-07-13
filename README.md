# IpBypassPlusFrag

> **IPv4 DPI bypass proxy with real-SNI-preserving fragmentation** — built from [ZeroDPI](https://github.com/mhdr/ZeroDPI)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20termux-blue)

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
| **Smart scan stop** | `MAX_IP_SCAN` stops scanning after finding N healthy IPs |
| **Speed-focused scoring** | Upload speed weighted highest, then download, then latency |
| **IP stats dashboard** | Shows per-IP connection count, upload/download bytes |
| **TUI dashboard** | Ratatui-powered live stats |
| **JSON events** | `--json-events` for headless/Android controller integration |
| **Background rescan** | Periodic re-scanning with automatic target switching |
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
tar xzf ip-bypass-plus-frag-termux.zip
chmod +x ip-bypass-plus-frag
./ip-bypass-plus-frag --config config.toml
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
  -c, --config <PATH>           Path to config.toml
      --listen-host <HOST>      Override LISTEN_HOST
      --listen-port <PORT>      Override LISTEN_PORT
      --auto-select             Auto-select top-ranked candidate
      --no-tui                  Disable terminal UI
      --json-events             Emit JSON events to stdout
      --method <METHOD>         Override BYPASS_METHOD
      --scan-timeout <SECS>     Override SCAN_TIMEOUT_SECS
      --rescan-interval <SECS>  Override RESCAN_INTERVAL_SECS
      --bypass-timeout <SECS>   Override BYPASS_TIMEOUT_SECS
```

---

## Building from Source

### Prerequisites

- Rust toolchain (stable)
- For Windows builds: `x86_64-pc-windows-gnu` target
- For Termux builds: `aarch64-unknown-linux-musl` target + zig

### Build commands

```bash
# Windows
cargo +stable-x86_64-pc-windows-gnu build --release

# Termux (requires zig in PATH)
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

---

## Project Structure

```
IpBypassPlusFrag/
├── Cargo.toml                  # Workspace root
├── config.toml                 # Configuration
├── ip_list.txt                 # IP/CIDR list
├── .cargo/config.toml          # WINDIVERT_PATH env
├── crates/
│   ├── zerodpi-core/           # Core logic
│   │   └── src/
│   │       ├── config.rs       # Config parsing (ip_bypass_plus only)
│   │       ├── flow.rs         # Flow tracking (unchanged from ZeroDPI)
│   │       ├── handler.rs      # TCP state machine (unchanged)
│   │       ├── interceptor.rs  # Packet interception traits (unchanged)
│   │       ├── ip_scanner.rs   # IP scanning + scoring
│   │       ├── proxy.rs        # TCP relay + pool rotation
│   │       ├── net.rs          # Network helpers
│   │       └── methods/
│   │           ├── tls_record_frag.rs  # TLS record fragmentation
│   │           └── tcp_segmentation.rs # TCP-level segmentation
│   ├── zerodpi-platform/       # Platform backends
│   │   └── src/
│   │       ├── linux.rs        # NFQUEUE (unchanged from ZeroDPI)
│   │       └── windows.rs      # WinDivert (unchanged from ZeroDPI)
│   └── zerodpi/                # CLI binary
│       └── src/
│           ├── main.rs         # Entry point (ip_bypass_plus only)
│           ├── tui.rs          # Dashboard + selection UI
│           └── runtime_events.rs # JSON event emitter
└── dist/                       # Release archives
    ├── windows/
    └── termux/
```

---

## Credits

- Built on [ZeroDPI](https://github.com/mhdr/ZeroDPI) by ZeroDPI contributors
- DPI bypass techniques inspired by [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)
- Cross-compilation powered by [zig](https://ziglang.org/)

---

## License

MIT
