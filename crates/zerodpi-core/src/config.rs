//! Configuration loaded from `config.toml`.

use std::fmt;
use std::path::Path;

use serde::de;
use serde::{Deserialize, Serialize};

use crate::interceptor::LinuxFirewallBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Int32Range {
    pub min: i32,
    pub max: i32,
}

impl Int32Range {
    pub const fn exact(value: i32) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("range cannot be empty".into());
        }

        if let Some((start, end)) = input.split_once('-') {
            let min = parse_i32(start.trim())?;
            let max = parse_i32(end.trim())?;
            if max < min {
                return Err(format!("range '{input}' has max lower than min"));
            }
            Ok(Self { min, max })
        } else {
            Ok(Self::exact(parse_i32(input)?))
        }
    }

    pub fn validate_at_least(&self, field: &str, min_value: i32) -> anyhow::Result<()> {
        if self.min < min_value {
            anyhow::bail!("{field} must be >= {min_value}");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Int32Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(i32),
            Text(String),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Int(value) => Ok(Self::exact(value)),
            Repr::Text(value) => Self::parse(&value).map_err(de::Error::custom),
        }
    }
}

fn parse_i32(value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|_| format!("'{value}' is not a valid Int32 value"))
}

impl fmt::Display for Int32Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFragPackets {
    TlsHello,
    WriteRange { start: u32, end: u32 },
}

impl TlsFragPackets {
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.eq_ignore_ascii_case("tlshello") {
            return Ok(Self::TlsHello);
        }

        let parse_packet_index = |value: &str| -> Result<u32, String> {
            let parsed = value
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("'{value}' is not a valid packet index"))?;
            if parsed == 0 {
                return Err("packet indexes are 1-based and must be >= 1".into());
            }
            Ok(parsed)
        };

        let (start, end) = if let Some((start, end)) = input.split_once('-') {
            (parse_packet_index(start)?, parse_packet_index(end)?)
        } else {
            let index = parse_packet_index(input)?;
            (index, index)
        };

        if end < start {
            return Err(format!("packet range '{input}' has end lower than start"));
        }

        Ok(Self::WriteRange { start, end })
    }

    pub fn includes_write(self, write_index: u32) -> bool {
        match self {
            Self::TlsHello => false,
            Self::WriteRange { start, end } => (start..=end).contains(&write_index),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Config {
    /// Local address the proxy listens on (e.g. `0.0.0.0` or `127.0.0.1`).
    pub LISTEN_HOST: String,

    /// Local port the proxy listens on.
    pub LISTEN_PORT: u16,

    /// Path to the IP list file (ip_bypass_plus mode).
    /// One entry per line: plain IPs (IPv4 only for ip_bypass_plus) or CIDR ranges.
    #[serde(default = "default_ip_list")]
    pub IP_LIST: String,

    /// Number of IPs to keep in the rotation pool.
    /// 1 = single IP mode (manual selection), >1 = multi-IP pool mode (auto-select top N).
    #[serde(default = "default_ip_pool")]
    pub IP_POOL: usize,

    /// Maximum number of IPs to scan from the selected range. 0 = unlimited.
    #[serde(default)]
    pub MAX_IP_SCAN: usize,

    /// Per-probe timeout in seconds.
    #[serde(default = "default_scan_timeout")]
    pub SCAN_TIMEOUT_SECS: u64,

    /// When `true` the application automatically picks the top-ranked entry
    /// after scanning instead of showing the manual selection table.
    #[serde(default)]
    pub AUTO_SELECT: bool,

    /// Rescan interval in seconds. Set to `0` to disable periodic rescanning.
    #[serde(default)]
    pub RESCAN_INTERVAL_SECS: u64,

    /// Minimum score required before a background rescan is allowed to
    /// switch the active target. Default: `1`.
    #[serde(default = "default_sni_switch_min_score")]
    pub SNI_SWITCH_MIN_SCORE: u8,

    /// Operating mode. Only "ip_bypass_plus" is supported.
    #[serde(default = "default_mode")]
    pub MODE: String,

    /// If set, skip the IP scan and use this IP directly.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub SELECTED_IP: Option<String>,

    /// SNI hostname used *only* during the TLS phase of IP scanning.
    #[serde(default = "default_ip_scan_sni")]
    pub IP_SCAN_SNI: String,

    /// Maximum number of host addresses expanded from a single IPv6 CIDR.
    #[serde(default = "default_ipv6_max_hosts")]
    pub IPV6_MAX_HOSTS: u64,

    /// Bypass method. Supported: "tls_record_frag", "tls_frag".
    #[serde(default = "default_method")]
    pub BYPASS_METHOD: String,

    /// (Linux only) NFQUEUE queue number.
    #[serde(default = "default_queue_num")]
    pub NFQUEUE_NUM: u16,

    /// (Linux only) Firewall rule backend.
    #[serde(default = "default_linux_firewall_backend")]
    pub LINUX_FIREWALL_BACKEND: String,

    // -----------------------------------------------------------------------
    // tls_record_frag method parameters
    // -----------------------------------------------------------------------
    /// Maximum bytes placed in each TLS record fragment.
    #[serde(default = "default_tls_frag_size")]
    pub TLS_RECORD_FRAG_SIZE: usize,

    /// Whether to set the TCP `PSH` flag on the fragmented packet.
    #[serde(default = "default_true")]
    pub TLS_RECORD_FRAG_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the fragmented packet.
    #[serde(default = "default_true")]
    pub TLS_RECORD_FRAG_BUMP_IP_IDENT: bool,

    // -----------------------------------------------------------------------
    // tls_frag method parameters
    // -----------------------------------------------------------------------
    /// Which client data should be fragmented.
    #[serde(default = "default_tls_frag_packets")]
    pub TLS_FRAG_PACKETS: String,

    /// Xray-style fragment length range, in bytes.
    #[serde(default = "default_tls_frag_length")]
    pub TLS_FRAG_LENGTH: Option<Int32Range>,

    /// Xray-style interval range, in milliseconds, between fragments.
    #[serde(default = "default_tls_frag_interval_ms")]
    pub TLS_FRAG_INTERVAL_MS: Int32Range,

    /// Legacy fixed fragment length fallback.
    #[serde(default = "default_tcp_seg_size")]
    pub TCP_SEG_SIZE: usize,

    /// Whether to set `TCP_NODELAY` on the upstream socket.
    #[serde(default = "default_true")]
    pub TCP_SEG_NODELAY: bool,

    // -----------------------------------------------------------------------
    // Proxy timing
    // -----------------------------------------------------------------------
    /// Time to wait for the bypass to complete before giving up.
    #[serde(default = "default_bypass_timeout")]
    pub BYPASS_TIMEOUT_SECS: u64,

    /// Maximum lifetime for an established relay before rotation.
    /// `0` disables relay rotation.
    #[serde(default)]
    pub RELAY_MAX_LIFETIME_SECS: u64,

    // -----------------------------------------------------------------------
    // Scanner tuning
    // -----------------------------------------------------------------------
    /// Max concurrent TCP connections in IP phase 1.
    #[serde(default = "default_ip_max_p1_concurrent")]
    pub IP_MAX_P1_CONCURRENT: usize,

    /// Max concurrent TLS probes in IP phase 2.
    #[serde(default = "default_ip_max_p2_concurrent")]
    pub IP_MAX_P2_CONCURRENT: usize,

    /// Max bytes downloaded for speed tests.
    #[serde(default = "default_scan_download_cap")]
    pub SCAN_DOWNLOAD_CAP: usize,

    /// Max bytes uploaded for upload speed tests.
    #[serde(default = "default_scan_upload_cap")]
    pub SCAN_UPLOAD_CAP: usize,

    /// Candidate-relative HTTP path used for upload speed tests.
    #[serde(default = "default_scan_upload_path")]
    pub SCAN_UPLOAD_PATH: String,

    /// Max valid TCP latency for scoring (ms).
    #[serde(default = "default_tcp_latency_cap_ms")]
    pub TCP_LATENCY_CAP_MS: f64,

    /// Max valid TLS latency for scoring (ms).
    #[serde(default = "default_tls_latency_cap_ms")]
    pub TLS_LATENCY_CAP_MS: f64,

    /// Max valid TTFB for scoring (ms).
    #[serde(default = "default_ttfb_cap_ms")]
    pub TTFB_CAP_MS: f64,

    /// Download speed cap for scoring (bytes/sec).
    #[serde(default = "default_speed_cap_bps")]
    pub SPEED_CAP_BPS: f64,

    /// Upload speed cap for scoring (bytes/sec).
    #[serde(default = "default_upload_speed_cap_bps")]
    pub UPLOAD_SPEED_CAP_BPS: f64,

    /// Optional path to write scan results as a JSON file.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub SCAN_OUTPUT: Option<String>,
}

fn empty_string_as_none<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => Ok(Some(s.to_owned())),
    }
}

fn default_mode() -> String {
    "ip_bypass_plus".into()
}
fn default_ip_list() -> String {
    "ip_list.txt".into()
}
fn default_ip_pool() -> usize {
    1
}
fn default_scan_timeout() -> u64 {
    5
}
fn default_method() -> String {
    "tls_frag".into()
}
fn default_queue_num() -> u16 {
    1
}
fn default_linux_firewall_backend() -> String {
    LinuxFirewallBackend::default().as_str().into()
}
fn default_true() -> bool {
    true
}
fn default_tls_frag_size() -> usize {
    1
}
fn default_tls_frag_packets() -> String {
    "1-3".into()
}
fn default_tls_frag_length() -> Option<Int32Range> {
    Some(Int32Range { min: 100, max: 200 })
}
fn default_tls_frag_interval_ms() -> Int32Range {
    Int32Range { min: 10, max: 20 }
}
fn default_tcp_seg_size() -> usize {
    1
}
fn default_bypass_timeout() -> u64 {
    20
}
fn default_ip_scan_sni() -> String {
    "cloudflare.com".into()
}
fn default_ipv6_max_hosts() -> u64 {
    65536
}
fn default_ip_max_p1_concurrent() -> usize {
    128
}
fn default_ip_max_p2_concurrent() -> usize {
    32
}
fn default_scan_download_cap() -> usize {
    10_240
}
fn default_scan_upload_cap() -> usize {
    10_240
}
fn default_scan_upload_path() -> String {
    "/".into()
}
fn default_tcp_latency_cap_ms() -> f64 {
    500.0
}
fn default_tls_latency_cap_ms() -> f64 {
    1_000.0
}
fn default_ttfb_cap_ms() -> f64 {
    2_000.0
}
fn default_speed_cap_bps() -> f64 {
    2_048_000.0
}
fn default_upload_speed_cap_bps() -> f64 {
    2_048_000.0
}
fn default_sni_switch_min_score() -> u8 {
    1
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.SCAN_TIMEOUT_SECS == 0 {
            anyhow::bail!("SCAN_TIMEOUT_SECS must be > 0");
        }
        if self.BYPASS_TIMEOUT_SECS == 0 {
            anyhow::bail!("BYPASS_TIMEOUT_SECS must be > 0");
        }
        if self.SNI_SWITCH_MIN_SCORE > 100 {
            anyhow::bail!("SNI_SWITCH_MIN_SCORE must be <= 100");
        }
        if self.SCAN_DOWNLOAD_CAP == 0 {
            anyhow::bail!("SCAN_DOWNLOAD_CAP must be > 0");
        }
        if self.SCAN_UPLOAD_CAP == 0 {
            anyhow::bail!("SCAN_UPLOAD_CAP must be > 0");
        }
        if self.SCAN_UPLOAD_PATH.is_empty()
            || !self.SCAN_UPLOAD_PATH.starts_with('/')
            || self.SCAN_UPLOAD_PATH.contains('\r')
            || self.SCAN_UPLOAD_PATH.contains('\n')
        {
            anyhow::bail!(
                "SCAN_UPLOAD_PATH must be a non-empty HTTP path starting with '/' and containing no CR/LF"
            );
        }
        if !self.SPEED_CAP_BPS.is_finite() || self.SPEED_CAP_BPS <= 0.0 {
            anyhow::bail!("SPEED_CAP_BPS must be a finite value > 0");
        }
        if !self.UPLOAD_SPEED_CAP_BPS.is_finite() || self.UPLOAD_SPEED_CAP_BPS <= 0.0 {
            anyhow::bail!("UPLOAD_SPEED_CAP_BPS must be a finite value > 0");
        }
        if self.MODE != "ip_bypass_plus" {
            anyhow::bail!(
                "Unknown MODE '{}'. Only \"ip_bypass_plus\" is supported",
                self.MODE
            );
        }
        if self.IP_POOL == 0 {
            anyhow::bail!("IP_POOL must be >= 1");
        }
        if !matches!(
            self.BYPASS_METHOD.as_str(),
            "tls_record_frag" | "tls_frag"
        ) {
            anyhow::bail!(
                "Unknown BYPASS_METHOD '{}'. Valid values: \"tls_record_frag\", \"tls_frag\"",
                self.BYPASS_METHOD
            );
        }
        if self.TLS_RECORD_FRAG_SIZE == 0 {
            anyhow::bail!("TLS_RECORD_FRAG_SIZE must be >= 1");
        }
        if self.TCP_SEG_SIZE == 0 {
            anyhow::bail!("TCP_SEG_SIZE must be >= 1");
        }
        if self.TCP_SEG_SIZE > i32::MAX as usize {
            anyhow::bail!("TCP_SEG_SIZE must be <= i32::MAX");
        }
        let _ = self.tls_frag_packets()?;
        self.tls_frag_length_range()?
            .validate_at_least("TLS_FRAG_LENGTH", 1)?;
        self.TLS_FRAG_INTERVAL_MS
            .validate_at_least("TLS_FRAG_INTERVAL_MS", 0)?;
        if LinuxFirewallBackend::parse(&self.LINUX_FIREWALL_BACKEND).is_none() {
            anyhow::bail!(
                "Unknown LINUX_FIREWALL_BACKEND '{}'. Valid values: \"iptables\", \"nftables\"",
                self.LINUX_FIREWALL_BACKEND
            );
        }
        if let Some(ref ip) = self.SELECTED_IP {
            let parsed = ip
                .parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("SELECTED_IP '{}' is not a valid IP address", ip))?;
            if parsed.is_ipv6() {
                anyhow::bail!("ip_bypass_plus is IPv4-only; SELECTED_IP '{ip}' is IPv6");
            }
        }
        Ok(())
    }

    pub fn tls_frag_packets(&self) -> anyhow::Result<TlsFragPackets> {
        TlsFragPackets::parse(&self.TLS_FRAG_PACKETS)
            .map_err(|e| anyhow::anyhow!("TLS_FRAG_PACKETS is invalid: {e}"))
    }

    pub fn tls_frag_length_range(&self) -> anyhow::Result<Int32Range> {
        if let Some(range) = self.TLS_FRAG_LENGTH {
            return Ok(range);
        }
        let value = i32::try_from(self.TCP_SEG_SIZE)
            .map_err(|_| anyhow::anyhow!("TCP_SEG_SIZE must be <= i32::MAX"))?;
        Ok(Int32Range::exact(value))
    }

    pub fn linux_firewall_backend(&self) -> LinuxFirewallBackend {
        LinuxFirewallBackend::parse(&self.LINUX_FIREWALL_BACKEND).unwrap_or_default()
    }
}
