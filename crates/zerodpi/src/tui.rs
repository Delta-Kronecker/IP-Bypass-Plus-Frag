//! ratatui-based UI for ip_bypass_plus mode: IP scan-progress view,
//! interactive IP selection table, and live proxy dashboard.

use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState};
use ratatui::Terminal;
use tokio::sync::mpsc;

use zerodpi_core::config::Config;
use zerodpi_core::flow::BypassOutcome;
use zerodpi_core::ip_scanner::{IpProbeEntry, IpScanEvent};
use zerodpi_core::proxy::{ProxyEvent, IpPoolEntry};

type Term = Terminal<CrosstermBackend<Stdout>>;
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn is_tui_active() -> bool {
    TUI_ACTIVE.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Per-cell color helpers
// ---------------------------------------------------------------------------

const TCP_LOW_MS: u64 = 100;
const TCP_HIGH_MS: u64 = 300;

fn score_style(score: u8) -> Style {
    let color = if score >= 60 {
        Color::Green
    } else if score >= 30 {
        Color::Yellow
    } else {
        Color::Red
    };
    Style::default().fg(color)
}

fn tls_style(tls_ok: bool) -> Style {
    if tls_ok {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
    }
}

fn tcp_style(latency_ms: Option<u64>) -> Style {
    let color = match latency_ms {
        Some(ms) if ms < TCP_LOW_MS => Color::Green,
        Some(ms) if ms <= TCP_HIGH_MS => Color::Yellow,
        _ => Color::Red,
    };
    Style::default().fg(color)
}

fn http_style(status: Option<u16>) -> Style {
    let color = match status {
        Some(s) if (200..300).contains(&s) => Color::Green,
        Some(s) if (300..400).contains(&s) => Color::Yellow,
        Some(_) => Color::Red,
        None => Color::Gray,
    };
    Style::default().fg(color)
}

fn cert_style(valid: bool) -> Style {
    if valid {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
    }
}

fn label_style() -> Style {
    Style::default().fg(Color::Gray)
}

fn fmt_rate_bps(speed: Option<f64>) -> String {
    speed
        .map(|bps| {
            if bps >= 1_048_576.0 {
                format!("{:.1}MB/s", bps / 1_048_576.0)
            } else {
                format!("{:.0}KB/s", bps / 1024.0)
            }
        })
        .unwrap_or_else(|| "—".into())
}

// ---------------------------------------------------------------------------
// Dashboard mode descriptor
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum DashboardInfo {
    IpBypassPlus { ip: IpAddr },
    IpBypassPlusPool { active_ip: IpAddr, pool: Vec<IpPoolEntry> },
}

// ---------------------------------------------------------------------------
// Terminal lifecycle helpers
// ---------------------------------------------------------------------------

pub fn enter_tui() -> anyhow::Result<Term> {
    enable_raw_mode()?;
    TUI_ACTIVE.store(true, Ordering::SeqCst);
    let mut stdout = io::stdout();
    if let Err(e) = execute!(stdout, EnterAlternateScreen) {
        TUI_ACTIVE.store(false, Ordering::SeqCst);
        let _ = disable_raw_mode();
        return Err(e.into());
    }
    let backend = CrosstermBackend::new(stdout);
    match Terminal::new(backend) {
        Ok(terminal) => Ok(terminal),
        Err(e) => {
            TUI_ACTIVE.store(false, Ordering::SeqCst);
            let _ = disable_raw_mode();
            Err(e.into())
        }
    }
}

pub fn leave_tui(mut terminal: Term) -> anyhow::Result<()> {
    let raw_result = disable_raw_mode();
    let leave_result = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let cursor_result = terminal.show_cursor();
    TUI_ACTIVE.store(false, Ordering::SeqCst);
    raw_result?;
    leave_result?;
    cursor_result?;
    Ok(())
}

/// Show mode selection: single IP or multi-IP pool.
///
/// Returns `true` if user selected "use multi ip", `false` for "select 1 ip".
pub fn run_mode_selection(terminal: &mut Term) -> anyhow::Result<bool> {
    let mut selected: usize = 0;
    let options = [
        ("select 1 ip", "Pick a single best IP manually"),
        ("use multi ip", "Auto-select top IPs, rotate connections"),
    ];

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(3),
                ])
                .split(area);

            let header = Paragraph::new("IP Bypass Plus — Choose Mode")
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(header, chunks[0]);

            let rows: Vec<Row> = options
                .iter()
                .enumerate()
                .map(|(i, (title, desc))| {
                    let style = if i == selected {
                        Style::default()
                            .bg(Color::Blue)
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Row::new(vec![
                        Cell::from(if i == selected { "▶ " } else { "  " }).style(style),
                        Cell::from(*title).style(style),
                        Cell::from(*desc).style(
                            if i == selected {
                                Style::default().fg(Color::White)
                            } else {
                                Style::default().fg(Color::Gray)
                            },
                        ),
                    ])
                })
                .collect();

            let widths = [
                Constraint::Length(3),
                Constraint::Length(16),
                Constraint::Min(30),
            ];
            let table = Table::new(rows, widths)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Select Operation Mode "),
                );
            frame.render_widget(table, chunks[1]);

            let help_spans: Line = Line::from(vec![
                Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
                Span::raw("navigate  "),
                Span::styled(" Enter ", Style::default().fg(Color::Green)),
                Span::raw("confirm  "),
            ]);
            let help = Paragraph::new(help_spans).block(Block::default().borders(Borders::ALL));
            frame.render_widget(help, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if selected + 1 < options.len() {
                            selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        return Ok(selected == 1);
                    }
                    KeyCode::Char('1') => return Ok(false),
                    KeyCode::Char('2') => return Ok(true),
                    _ => {}
                }
            }
        }
    }
}

/// Show CIDR range selection. Returns the index of the selected range.
pub fn run_range_selection(
    terminal: &mut Term,
    ranges: &[(String, usize)],
) -> anyhow::Result<usize> {
    if ranges.is_empty() {
        anyhow::bail!("no CIDR ranges to select from");
    }

    let mut selected: usize = 0;

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(3),
                ])
                .split(area);

            let header = Paragraph::new("IP Bypass Plus — Select CIDR Range")
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(header, chunks[0]);

            let rows: Vec<Row> = ranges
                .iter()
                .enumerate()
                .map(|(i, (range, count))| {
                    let style = if i == selected {
                        Style::default()
                            .bg(Color::Blue)
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Row::new(vec![
                        Cell::from(if i == selected { "▶ " } else { "  " }).style(style),
                        Cell::from(range.clone()).style(style),
                        Cell::from(format!("{} hosts", count)).style(
                            if i == selected {
                                Style::default().fg(Color::White)
                            } else {
                                Style::default().fg(Color::Gray)
                            },
                        ),
                    ])
                })
                .collect();

            let widths = [
                Constraint::Length(3),
                Constraint::Min(20),
                Constraint::Length(16),
            ];
            let table = Table::new(rows, widths)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" CIDR Ranges "),
                );
            frame.render_widget(table, chunks[1]);

            let help_spans: Line = Line::from(vec![
                Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
                Span::raw("navigate  "),
                Span::styled(" Enter ", Style::default().fg(Color::Green)),
                Span::raw("confirm  "),
            ]);
            let help = Paragraph::new(help_spans).block(Block::default().borders(Borders::ALL));
            frame.render_widget(help, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if selected + 1 < ranges.len() {
                            selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        return Ok(selected);
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IP scan-progress view
// ---------------------------------------------------------------------------

pub fn run_ip_scan_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<IpScanEvent>,
    total_ips: usize,
) -> anyhow::Result<(Vec<IpProbeEntry>, bool)> {
    let mut arrived: Vec<IpProbeEntry> = Vec::new();
    let mut tcp_done: usize = 0;

    loop {
        loop {
            match rx.try_recv() {
                Ok(IpScanEvent::TcpDone { tcp_tested }) => {
                    tcp_done = tcp_tested;
                }
                Ok(IpScanEvent::ProbeComplete(entry)) => {
                    arrived.push(entry);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    draw_ip_scan_progress(terminal, &arrived, tcp_done, total_ips)?;
                    return Ok((arrived, false));
                }
            }
        }

        draw_ip_scan_progress(terminal, &arrived, tcp_done, total_ips)?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press
                    && matches!(
                        k.code,
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
                    )
                {
                    return Ok((arrived, true));
                }
            }
        }
    }
}

fn draw_ip_scan_progress(
    terminal: &mut Term,
    arrived: &[IpProbeEntry],
    tcp_done: usize,
    total_ips: usize,
) -> anyhow::Result<()> {
    let probe_count = arrived.len();
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(5),
            ])
            .split(area);

        let header = Paragraph::new("ZeroDPI — Scanning IPs…")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        let ratio = if total_ips == 0 {
            0.0
        } else {
            (tcp_done as f64 / total_ips as f64).min(1.0)
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Progress "))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(format!(
                "{tcp_done}/{total_ips} TCP tested — {probe_count} TLS probed"
            ));
        frame.render_widget(gauge, chunks[1]);

        let rows: Vec<Row> = arrived
            .iter()
            .map(|e| {
                let tcp_str = e
                    .tcp_latency_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "fail".into());
                let tls_str = if e.tls_ok {
                    e.tls_latency_ms
                        .map(|ms| format!("✓ {ms}ms"))
                        .unwrap_or_else(|| "✓".into())
                } else {
                    "✗".into()
                };
                let ttfb_str = e
                    .ttfb_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let cert = if e.cert_valid { "✓" } else { "✗" };
                let down_str = fmt_rate_bps(e.download_bps);
                let up_str = fmt_rate_bps(e.upload_bps);
                let http_str = e
                    .http_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".into());
                Row::new(vec![
                    Cell::from(e.score.to_string()).style(score_style(e.score)),
                    Cell::from(e.ip.to_string()),
                    Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                    Cell::from(tls_str).style(tls_style(e.tls_ok)),
                    Cell::from(cert).style(cert_style(e.cert_valid)),
                    Cell::from(ttfb_str),
                    Cell::from(down_str),
                    Cell::from(up_str),
                    Cell::from(http_str).style(http_style(e.http_status)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(5),
            Constraint::Min(36),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
                ])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live results "),
            );
        frame.render_widget(table, chunks[2]);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IP selection table
// ---------------------------------------------------------------------------

pub fn run_ip_selection(
    terminal: &mut Term,
    entries: &[IpProbeEntry],
) -> anyhow::Result<IpProbeEntry> {
    if entries.is_empty() {
        anyhow::bail!("no IP candidates to select from");
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_ip_selection(frame, entries, &mut state))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(entries.len() - 1)));
                    }
                    KeyCode::Enter => {
                        let idx = state.selected().unwrap_or(0);
                        return Ok(entries[idx].clone());
                    }
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                        return Ok(entries[0].clone());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_ip_selection(frame: &mut ratatui::Frame, entries: &[IpProbeEntry], state: &mut TableState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new("ZeroDPI — Select IP")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rank = (i + 1).to_string();
            let rank_style = if i == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let tcp_str = e
                .tcp_latency_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "fail".into());
            let tls_str = if e.tls_ok {
                e.tls_latency_ms
                    .map(|ms| format!("✓ {ms}ms"))
                    .unwrap_or_else(|| "✓".into())
            } else {
                "✗".into()
            };
            let ttfb_str = e
                .ttfb_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let cert = if e.cert_valid { "✓" } else { "✗" };
            let down_str = fmt_rate_bps(e.download_bps);
            let up_str = fmt_rate_bps(e.upload_bps);
            let http_str = e
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(rank).style(rank_style),
                Cell::from(e.score.to_string()).style(score_style(e.score)),
                Cell::from(e.ip.to_string()),
                Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                Cell::from(tls_str).style(tls_style(e.tls_ok)),
                Cell::from(cert).style(cert_style(e.cert_valid)),
                Cell::from(ttfb_str),
                Cell::from(down_str),
                Cell::from(up_str),
                Cell::from(http_str).style(http_style(e.http_status)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(36),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ranked IP candidates "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[1], state);

    let help_spans: Line = Line::from(vec![
        Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
        Span::raw("navigate  "),
        Span::styled(" Enter ", Style::default().fg(Color::Green)),
        Span::raw("select  "),
        Span::styled(" q / Esc ", Style::default().fg(Color::Red)),
        Span::raw("pick rank-1 "),
    ]);
    let help = Paragraph::new(help_spans).block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

// ---------------------------------------------------------------------------
// Live proxy dashboard
// ---------------------------------------------------------------------------

const MAX_RECORDS: usize = 200;
const ACTIVE_RATE_BPS: f64 = 50.0;
const NON_RELAYING_TOP_GRACE: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficDirection {
    Idle,
    Upload,
    Download,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnStatus {
    Connecting,
    Relaying,
    Done,
    Rotated,
    Failed,
}

impl ConnStatus {
    fn label(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "Connecting",
            ConnStatus::Relaying => "Relaying",
            ConnStatus::Done => "Done",
            ConnStatus::Rotated => "Rotated",
            ConnStatus::Failed => "Failed",
        }
    }

    fn style(&self) -> Style {
        match self {
            ConnStatus::Connecting => Style::default().fg(Color::Yellow),
            ConnStatus::Relaying => Style::default().fg(Color::Cyan),
            ConnStatus::Done => Style::default().fg(Color::Green),
            ConnStatus::Rotated => Style::default().fg(Color::Magenta),
            ConnStatus::Failed => Style::default().fg(Color::Red),
        }
    }
}

fn traffic_direction(
    status: &ConnStatus,
    upload_bps: f64,
    download_bps: f64,
) -> Option<TrafficDirection> {
    if !matches!(status, ConnStatus::Relaying) {
        return None;
    }

    match (
        upload_bps >= ACTIVE_RATE_BPS,
        download_bps >= ACTIVE_RATE_BPS,
    ) {
        (true, true) => Some(TrafficDirection::Bidirectional),
        (true, false) => Some(TrafficDirection::Upload),
        (false, true) => Some(TrafficDirection::Download),
        (false, false) => Some(TrafficDirection::Idle),
    }
}

fn connection_row_style(record: &ConnectionRecord) -> Style {
    match record.status {
        ConnStatus::Connecting => Style::default().bg(Color::Indexed(58)),
        ConnStatus::Relaying => {
            match traffic_direction(&record.status, record.rate_c2s_bps, record.rate_s2c_bps) {
                Some(TrafficDirection::Upload) => Style::default().bg(Color::Indexed(22)),
                Some(TrafficDirection::Download) => Style::default().bg(Color::Indexed(24)),
                Some(TrafficDirection::Bidirectional) => Style::default().bg(Color::Indexed(29)),
                Some(TrafficDirection::Idle) | None => Style::default(),
            }
        }
        ConnStatus::Failed => Style::default().bg(Color::Indexed(52)),
        ConnStatus::Done | ConnStatus::Rotated => Style::default(),
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
enum FilterStatus {
    #[default]
    All,
    Active,
    Done,
    Failed,
}

impl FilterStatus {
    fn label(&self) -> &'static str {
        match self {
            FilterStatus::All => "All",
            FilterStatus::Active => "Active",
            FilterStatus::Done => "Done",
            FilterStatus::Failed => "Failed",
        }
    }

    fn next(&self) -> Self {
        match self {
            FilterStatus::All => FilterStatus::Active,
            FilterStatus::Active => FilterStatus::Done,
            FilterStatus::Done => FilterStatus::Failed,
            FilterStatus::Failed => FilterStatus::All,
        }
    }

    fn matches(&self, status: &ConnStatus) -> bool {
        match self {
            FilterStatus::All => true,
            FilterStatus::Active => matches!(status, ConnStatus::Connecting | ConnStatus::Relaying),
            FilterStatus::Done => matches!(status, ConnStatus::Done | ConnStatus::Rotated),
            FilterStatus::Failed => matches!(status, ConnStatus::Failed),
        }
    }
}

struct ConnectionRecord {
    started_at: SystemTime,
    start_instant: Instant,
    end_instant: Option<Instant>,
    src_port: u16,
    peer: SocketAddr,
    upstream_ip: IpAddr,
    status: ConnStatus,
    status_changed_at: Instant,
    c2s_bytes: u64,
    s2c_bytes: u64,
    rate_c2s_bps: f64,
    rate_s2c_bps: f64,
    last_snapshot: Option<(Instant, u64, u64)>,
}

impl ConnectionRecord {
    fn is_active(&self) -> bool {
        matches!(self.status, ConnStatus::Connecting | ConnStatus::Relaying)
    }

    fn set_status(&mut self, status: ConnStatus, now: Instant) {
        if self.status != status {
            self.status = status;
            self.status_changed_at = now;
        }
    }

    fn duration_str(&self) -> String {
        let elapsed = self
            .end_instant
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(self.start_instant);
        let ms = elapsed.as_millis();
        if ms < 1000 {
            format!("{}ms", ms)
        } else {
            format!("{:.1}s", elapsed.as_secs_f64())
        }
    }
}

fn connection_display_rank(record: &ConnectionRecord, now: Instant) -> u8 {
    if matches!(record.status, ConnStatus::Relaying) {
        0
    } else if now.saturating_duration_since(record.status_changed_at) < NON_RELAYING_TOP_GRACE {
        1
    } else {
        2
    }
}

fn ordered_connection_records(state: &DashboardState, now: Instant) -> Vec<&ConnectionRecord> {
    let mut filtered: Vec<(usize, &ConnectionRecord)> = state
        .records
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            if !state.filter.matches(&r.status) {
                return false;
            }
            // In pool mode, only show connections to pool IPs
            if !state.pool_ips.is_empty() && !state.pool_ips.contains(&r.upstream_ip) {
                return false;
            }
            true
        })
        .collect();

    filtered.sort_by_key(|(idx, record)| (connection_display_rank(record, now), *idx));
    filtered.into_iter().map(|(_, record)| record).collect()
}

fn prune_connection_records(records: &mut VecDeque<ConnectionRecord>) {
    while records.len() > MAX_RECORDS {
        let Some(idx) = records.iter().rposition(|record| !record.is_active()) else {
            break;
        };
        records.remove(idx);
    }
}

struct DashboardState {
    records: VecDeque<ConnectionRecord>,
    total: u64,
    bypasses_ok: u64,
    bypasses_failed: u64,
    active: u64,
    total_c2s: u64,
    total_s2c: u64,
    scroll_offset: usize,
    auto_scroll: bool,
    filter: FilterStatus,
    active_ip: Option<IpAddr>,
    pool_ips: Vec<IpAddr>,
    start: Instant,
    channel_closed: bool,
    cumulative_conns: std::collections::HashMap<IpAddr, u64>,
    cumulative_up: std::collections::HashMap<IpAddr, u64>,
    cumulative_down: std::collections::HashMap<IpAddr, u64>,
}

fn fmt_time(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else {
        format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
    }
}

fn fmt_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn fmt_rate(bps: f64) -> String {
    if bps < ACTIVE_RATE_BPS {
        return "—".to_string();
    }
    if bps < 1024.0 {
        format!("{:.0}B/s", bps)
    } else if bps < 1_048_576.0 {
        format!("{:.1}K/s", bps / 1024.0)
    } else {
        format!("{:.1}M/s", bps / 1_048_576.0)
    }
}

fn fmt_stats_field(value: impl AsRef<str>) -> String {
    format!("{:>8}", value.as_ref())
}

fn live_transfer_totals(state: &DashboardState) -> (u64, u64) {
    let active_c2s: u64 = state
        .records
        .iter()
        .filter(|r| r.end_instant.is_none())
        .map(|r| r.c2s_bytes)
        .sum();
    let active_s2c: u64 = state
        .records
        .iter()
        .filter(|r| r.end_instant.is_none())
        .map(|r| r.s2c_bytes)
        .sum();

    (
        state.total_c2s.saturating_add(active_c2s),
        state.total_s2c.saturating_add(active_s2c),
    )
}

pub fn run_dashboard(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<ProxyEvent>,
    info: &DashboardInfo,
    cfg: &Config,
) -> anyhow::Result<()> {
    let active_ip = match info {
        DashboardInfo::IpBypassPlus { ip } => Some(*ip),
        DashboardInfo::IpBypassPlusPool { active_ip, .. } => Some(*active_ip),
    };
    let pool_ips: Vec<IpAddr> = match info {
        DashboardInfo::IpBypassPlus { .. } => Vec::new(),
        DashboardInfo::IpBypassPlusPool { pool, .. } => pool.iter().map(|e| e.ip).collect(),
    };
    let mut state = DashboardState {
        records: VecDeque::with_capacity(MAX_RECORDS),
        total: 0,
        bypasses_ok: 0,
        bypasses_failed: 0,
        active: 0,
        total_c2s: 0,
        total_s2c: 0,
        scroll_offset: 0,
        auto_scroll: true,
        filter: FilterStatus::All,
        active_ip,
        pool_ips,
        start: Instant::now(),
        channel_closed: false,
        cumulative_conns: std::collections::HashMap::new(),
        cumulative_up: std::collections::HashMap::new(),
        cumulative_down: std::collections::HashMap::new(),
    };

    loop {
        let mut got_event = false;
        if !state.channel_closed {
            loop {
                match rx.try_recv() {
                    Ok(event) => {
                        apply_event(event, &mut state);
                        got_event = true;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        state.channel_closed = true;
                        break;
                    }
                }
            }
        }

        if state.auto_scroll && got_event {
            state.scroll_offset = 0;
        }

        draw_dashboard(terminal, &state, info, cfg)?;

        let filtered_len = state
            .records
            .iter()
            .filter(|r| state.filter.matches(&r.status))
            .count();

        let visible_rows = terminal
            .size()
            .map(|s| (s.height as usize).saturating_sub(14))
            .unwrap_or(10)
            .max(1);

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            return Ok(());
                        }
                        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.auto_scroll = false;
                            state.scroll_offset = state.scroll_offset.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.auto_scroll = false;
                            if filtered_len > 0 && state.scroll_offset + 1 < filtered_len {
                                state.scroll_offset += 1;
                            }
                        }
                        KeyCode::PageUp => {
                            state.auto_scroll = false;
                            state.scroll_offset = state.scroll_offset.saturating_sub(visible_rows);
                        }
                        KeyCode::PageDown => {
                            state.auto_scroll = false;
                            state.scroll_offset = (state.scroll_offset + visible_rows)
                                .min(filtered_len.saturating_sub(1));
                        }
                        KeyCode::Home => {
                            state.scroll_offset = 0;
                        }
                        KeyCode::End => {
                            state.auto_scroll = false;
                            state.scroll_offset = filtered_len.saturating_sub(1);
                        }
                        KeyCode::Char(' ') | KeyCode::Char('a') => {
                            state.auto_scroll = !state.auto_scroll;
                            if state.auto_scroll {
                                state.scroll_offset = 0;
                            }
                        }
                        KeyCode::Tab => {
                            state.filter = state.filter.next();
                            state.scroll_offset = 0;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn apply_event(event: ProxyEvent, state: &mut DashboardState) {
    match event {
        ProxyEvent::ListenerStarted { .. } => {}
        ProxyEvent::ConnectionAccepted { peer, src_port, upstream_ip } => {
            state.total += 1;
            state.active += 1;
            *state.cumulative_conns.entry(upstream_ip).or_insert(0) += 1;
            let now = Instant::now();
            let rec = ConnectionRecord {
                started_at: SystemTime::now(),
                start_instant: now,
                end_instant: None,
                src_port,
                peer,
                upstream_ip,
                status: ConnStatus::Connecting,
                status_changed_at: now,
                c2s_bytes: 0,
                s2c_bytes: 0,
                rate_c2s_bps: 0.0,
                rate_s2c_bps: 0.0,
                last_snapshot: None,
            };
            state.records.push_front(rec);
        }
        ProxyEvent::BypassComplete { src_port, outcome } => match outcome {
            BypassOutcome::FakeDataAcked => {
                state.bypasses_ok += 1;
                if let Some(r) = find_record(&mut state.records, src_port) {
                    r.set_status(ConnStatus::Relaying, Instant::now());
                }
            }
            BypassOutcome::UnexpectedClose => {
                state.bypasses_failed += 1;
                state.active = state.active.saturating_sub(1);
                if let Some(r) = find_record(&mut state.records, src_port) {
                    let now = Instant::now();
                    r.set_status(ConnStatus::Failed, now);
                    r.end_instant = Some(now);
                }
            }
        },
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes,
            s2c_bytes,
            reason,
        } => {
            state.active = state.active.saturating_sub(1);
            state.total_c2s += c2s_bytes;
            state.total_s2c += s2c_bytes;
            if let Some(r) = find_record(&mut state.records, src_port) {
                *state.cumulative_up.entry(r.upstream_ip).or_insert(0) += c2s_bytes;
                *state.cumulative_down.entry(r.upstream_ip).or_insert(0) += s2c_bytes;
                let now = Instant::now();
                let status = match reason {
                    zerodpi_core::proxy::RelayEndReason::Completed => ConnStatus::Done,
                    zerodpi_core::proxy::RelayEndReason::MaxLifetime => ConnStatus::Rotated,
                };
                r.set_status(status, now);
                r.c2s_bytes = c2s_bytes;
                r.s2c_bytes = s2c_bytes;
                r.rate_c2s_bps = 0.0;
                r.rate_s2c_bps = 0.0;
                r.end_instant = Some(now);
            }
        }
        ProxyEvent::RelayProgress {
            src_port,
            c2s_bytes,
            s2c_bytes,
        } => {
            if let Some(r) = find_record(&mut state.records, src_port) {
                let now = Instant::now();
                if let Some((prev_time, prev_c2s, prev_s2c)) = r.last_snapshot {
                    let secs = now.duration_since(prev_time).as_secs_f64().max(0.001);
                    r.rate_c2s_bps = c2s_bytes.saturating_sub(prev_c2s) as f64 / secs;
                    r.rate_s2c_bps = s2c_bytes.saturating_sub(prev_s2c) as f64 / secs;
                }
                r.c2s_bytes = c2s_bytes;
                r.s2c_bytes = s2c_bytes;
                r.last_snapshot = Some((now, c2s_bytes, s2c_bytes));
            }
        }
        ProxyEvent::ConnectionError { src_port, .. } => {
            state.bypasses_failed += 1;
            state.active = state.active.saturating_sub(1);
            if let Some(r) = find_record(&mut state.records, src_port) {
                let now = Instant::now();
                r.set_status(ConnStatus::Failed, now);
                r.end_instant = Some(now);
            }
        }
        ProxyEvent::IpTargetChanged { ip } => {
            state.active_ip = Some(ip);
        }
    }

    prune_connection_records(&mut state.records);
}

fn find_record(
    records: &mut VecDeque<ConnectionRecord>,
    src_port: u16,
) -> Option<&mut ConnectionRecord> {
    records.iter_mut().find(|r| r.src_port == src_port)
}

fn draw_dashboard(
    terminal: &mut Term,
    state: &DashboardState,
    info: &DashboardInfo,
    cfg: &Config,
) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),  // header
                Constraint::Length(3),  // stats
                Constraint::Min(5),     // connection log
                Constraint::Length(3),  // help
            ])
            .split(area);

        let title = if state.channel_closed {
            " ZeroDPI — Stopped "
        } else {
            " ZeroDPI — Running "
        };
        let uptime = fmt_uptime(state.start.elapsed());

        let header_lines = match info {
            DashboardInfo::IpBypassPlus { .. } => {
                let ip = state.active_ip.expect("IP dashboard state is initialised");
                vec![
                    Line::from(vec![
                        Span::styled("Mode: ", label_style()),
                        Span::styled(
                            "ip_bypass_plus",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw("   "),
                        Span::styled("Active IP: ", label_style()),
                        Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Listen: ", label_style()),
                        Span::styled(
                            format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Method: ", label_style()),
                        Span::styled(cfg.BYPASS_METHOD.clone(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Uptime: ", label_style()),
                        Span::styled(uptime, Style::default().fg(Color::White)),
                    ]),
                ]
            }
            DashboardInfo::IpBypassPlusPool { pool, .. } => {
                vec![
                    Line::from(vec![
                        Span::styled("Mode: ", label_style()),
                        Span::styled(
                            "ip_bypass_plus",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw("   "),
                        Span::styled("IPs: ", label_style()),
                        Span::styled(
                            format!("{} (round-robin)", pool.len()),
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw("   "),
                        Span::styled("Listen: ", label_style()),
                        Span::styled(
                            format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Method: ", label_style()),
                        Span::styled(cfg.BYPASS_METHOD.clone(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Uptime: ", label_style()),
                        Span::styled(uptime, Style::default().fg(Color::White)),
                    ]),
                ]
            }
        };
        let header =
            Paragraph::new(header_lines).block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(header, chunks[0]);

        let ok_pct = state
            .bypasses_ok
            .saturating_mul(100)
            .checked_div(state.total)
            .map_or_else(String::new, |pct| format!("({pct}%)"));
        let stats_line = Line::from(vec![
            Span::styled(" Total: ", label_style()),
            Span::styled(
                state.total.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("OK: ", label_style()),
            Span::styled(
                state.bypasses_ok.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {ok_pct}"), Style::default().fg(Color::Green)),
            Span::raw("  "),
            Span::styled("Failed: ", label_style()),
            Span::styled(
                state.bypasses_failed.to_string(),
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Active: ", label_style()),
            Span::styled(
                state.active.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]);
        let stats = Paragraph::new(stats_line)
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
        frame.render_widget(stats, chunks[1]);

        // Summary table: one row per pool IP with aggregated stats
        let now = Instant::now();
        let pool = match info {
            DashboardInfo::IpBypassPlusPool { pool, .. } => pool,
            _ => {
                // single IP mode - just show that one IP
                let ip = state.active_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                &vec![IpPoolEntry { ip, score: 0 }]
            }
        };

        let rows: Vec<Row> = pool
            .iter()
            .map(|e| {
                let count = state.cumulative_conns.get(&e.ip).copied().unwrap_or(0) as usize;
                let up = state.cumulative_up.get(&e.ip).copied().unwrap_or(0);
                let down = state.cumulative_down.get(&e.ip).copied().unwrap_or(0);
                let is_current = state.active_ip == Some(e.ip);
                Row::new(vec![
                    Cell::from(e.ip.to_string()).style(if is_current { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default() }),
                    Cell::from(e.score.to_string()).style(score_style(e.score)),
                    Cell::from(count.to_string()),
                    Cell::from(fmt_bytes(up)),
                    Cell::from(fmt_bytes(down)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
        ];
        let log_table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "IP Address",
                    "Score",
                    "Conns",
                    "↑ Bytes",
                    "↓ Bytes",
                ])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
            )
            .block(Block::default().borders(Borders::ALL).title(format!(" IP Stats — {} IPs round-robin ", pool.len())));
        frame.render_widget(log_table, chunks[2]);

        let auto_span = if state.auto_scroll {
            Span::styled(
                "[AUTO] ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "[PAUSED] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        };
        let help_line = Line::from(vec![
            auto_span,
            Span::styled(" ↑/↓ j/k ", Style::default().fg(Color::Yellow)),
            Span::raw("scroll  "),
            Span::styled(" PgUp/Dn ", Style::default().fg(Color::Yellow)),
            Span::raw("page  "),
            Span::styled(" Home/End ", Style::default().fg(Color::Yellow)),
            Span::raw("jump  "),
            Span::styled(" Space/a ", Style::default().fg(Color::Yellow)),
            Span::raw("auto  "),
            Span::styled(" Tab ", Style::default().fg(Color::Yellow)),
            Span::raw("filter  "),
            Span::styled(" q/Esc ", Style::default().fg(Color::Red)),
            Span::raw("quit "),
        ]);
        let help = Paragraph::new(help_line).block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[3]);
    })?;
    Ok(())
}
