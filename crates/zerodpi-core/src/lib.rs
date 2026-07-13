//! IP Bypass Plus core: platform-independent logic.
//!
//! - [`config`]: load/validate `config.toml`.
//! - [`flow`]: flow keys, per-connection state, the shared flow table.
//! - [`handler`]: stateful packet handler for TCP handshake tracking.
//! - [`interceptor`]: traits that platform packet-interception backends implement.
//! - [`methods`]: pluggable bypass methods (tls_record_frag, tcp_segmentation).
//! - [`net`]: small networking helpers (default-interface IP discovery).
//! - [`proxy`]: tokio TCP listener + bidirectional relay driving the bypass.
//! - [`ip_scanner`]: multi-phase IP scanner used in ip_bypass_plus mode.

pub mod config;
pub mod flow;
pub mod handler;
pub mod interceptor;
pub mod ip_scanner;
pub mod methods;
pub mod net;
pub mod proxy;
mod scanner_http;
