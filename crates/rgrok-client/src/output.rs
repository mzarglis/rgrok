use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crossterm::{cursor, execute, style};
use tokio::sync::mpsc;

/// Tracks tunnel statistics for the live dashboard
pub struct TunnelStats {
    pub connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    start: Instant,
}

impl TunnelStats {
    pub fn new() -> Self {
        Self {
            connections: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            start: Instant::now(),
        }
    }

    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn requests_per_minute(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return 0.0;
        }
        self.connections.load(Ordering::Relaxed) as f64 / (elapsed / 60.0)
    }
}

/// A log entry for a proxied request
pub struct RequestLogEntry {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration_ms: u64,
}

/// Print the tunnel connection information banner to the terminal
pub fn print_tunnel_info(public_url: &str, local_port: u16, inspect_port: u16) {
    let version = env!("CARGO_PKG_VERSION");
    let width = 58;
    let border = "═".repeat(width);

    println!();
    println!("╔{}╗", border);
    println!("║{:^width$}║", format!("rgrok v{}", version));
    println!("╠{}╣", border);
    println!(
        "║  {:<12} {:<width2$}║",
        "Tunnel:",
        public_url,
        width2 = width - 15
    );
    println!(
        "║  {:<12} {:<width2$}║",
        "Forwarding:",
        format!("http://localhost:{}", local_port),
        width2 = width - 15
    );
    if inspect_port > 0 {
        println!(
            "║  {:<12} {:<width2$}║",
            "Inspect:",
            format!("http://localhost:{}", inspect_port),
            width2 = width - 15
        );
    }
    println!("╠{}╣", border);
    println!(
        "║  {:<14}{:<10}{:<10}{:<width2$}║",
        "Connections",
        "Req/min",
        "Data In",
        "Data Out",
        width2 = width - 36
    );
}

/// Spawn the live dashboard updater that refreshes stats and prints request lines.
/// Returns a sender to submit request log entries.
pub fn spawn_dashboard(stats: Arc<TunnelStats>) -> mpsc::UnboundedSender<RequestLogEntry> {
    let (tx, mut rx) = mpsc::unbounded_channel::<RequestLogEntry>();

    // Print initial stats line
    print_stats_line(&stats);
    let width = 58;
    let border = "═".repeat(width);
    println!("╠{}╣", border);
    println!(
        "║  {:<8}{:<8}{:<18}{:<8}{:<width2$}║",
        "Time",
        "Method",
        "URL",
        "Status",
        "Duration",
        width2 = width - 44
    );
    println!("╚{}╝", border);
    println!();

    // Remember the line where we print stats (to update in-place)
    // We store the line count for the stats row
    let stats_clone = stats.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    update_stats_line(&stats_clone);
                }
                Some(entry) = rx.recv() => {
                    print_request_line(&entry.method, &entry.url, entry.status, entry.duration_ms);
                }
            }
        }
    });

    tx
}

fn print_stats_line(stats: &TunnelStats) {
    let conns = stats.connections.load(Ordering::Relaxed);
    let rpm = stats.requests_per_minute();
    let data_in = format_bytes(stats.bytes_in.load(Ordering::Relaxed));
    let data_out = format_bytes(stats.bytes_out.load(Ordering::Relaxed));
    let width = 58;

    print!(
        "║  {:<14}{:<10}{:<10}{:<width2$}║",
        conns,
        format!("{:.0}", rpm),
        data_in,
        data_out,
        width2 = width - 36
    );
}

fn update_stats_line(stats: &TunnelStats) {
    let mut stdout = std::io::stdout();
    let _ = execute!(stdout, cursor::SavePosition);
    // The stats line is a fixed number of lines above the current cursor.
    // We use a simpler approach: just print a carriage return-based update
    // on a separate mechanism. For now, the stats update is best-effort.
    let conns = stats.connections.load(Ordering::Relaxed);
    let rpm = stats.requests_per_minute();
    let data_in = format_bytes(stats.bytes_in.load(Ordering::Relaxed));
    let data_out = format_bytes(stats.bytes_out.load(Ordering::Relaxed));

    // We log stats as a trace-level update rather than trying to overwrite terminal lines,
    // since request log lines push the stats line up unpredictably.
    tracing::debug!(
        connections = conns,
        rpm = format!("{:.0}", rpm),
        data_in = %data_in,
        data_out = %data_out,
        "tunnel stats"
    );
    let _ = execute!(stdout, cursor::RestorePosition);
}

/// Print a single request log line to the terminal
pub fn print_request_line(method: &str, url: &str, status: u16, duration_ms: u64) {
    let now = chrono::Local::now().format("%H:%M:%S");
    let status_color = match status {
        0..=299 => style::Color::Green,
        300..=399 => style::Color::Cyan,
        400..=499 => style::Color::Yellow,
        _ => style::Color::Red,
    };

    let mut stdout = std::io::stdout();
    let _ = execute!(
        stdout,
        style::SetForegroundColor(style::Color::DarkGrey),
        style::Print(format!("  {:<8} ", now)),
        style::ResetColor,
        style::Print(format!("{:<7} ", method)),
        style::Print(format!("{:<30} ", truncate(url, 30))),
        style::SetForegroundColor(status_color),
        style::Print(format!("{:<5}", status)),
        style::ResetColor,
        style::Print(format!("  {}ms\n", duration_ms)),
    );
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn tunnel_stats_new_initializes_to_zero() {
        let stats = TunnelStats::new();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_in.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_out.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_connection_increments() {
        let stats = TunnelStats::new();
        stats.record_connection();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 1);
        stats.record_connection();
        stats.record_connection();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn record_bytes_in_tracks_correctly() {
        let stats = TunnelStats::new();
        stats.record_bytes_in(100);
        assert_eq!(stats.bytes_in.load(Ordering::Relaxed), 100);
        stats.record_bytes_in(250);
        assert_eq!(stats.bytes_in.load(Ordering::Relaxed), 350);
    }

    #[test]
    fn record_bytes_out_tracks_correctly() {
        let stats = TunnelStats::new();
        stats.record_bytes_out(500);
        assert_eq!(stats.bytes_out.load(Ordering::Relaxed), 500);
        stats.record_bytes_out(1500);
        assert_eq!(stats.bytes_out.load(Ordering::Relaxed), 2000);
    }

    #[test]
    fn requests_per_minute_returns_zero_when_just_started() {
        let stats = TunnelStats::new();
        stats.record_connection();
        // Elapsed time is essentially 0, which is < 1 second
        assert_eq!(stats.requests_per_minute(), 0.0);
    }

    #[test]
    fn format_bytes_displays_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_displays_kilobytes() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10240), "10.0 KB");
    }

    #[test]
    fn format_bytes_displays_megabytes() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn format_bytes_displays_gigabytes() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hi", 2), "hi");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        assert_eq!(truncate("abcdefghij", 7), "abcd...");
        assert_eq!(truncate("/very/long/url/path/here", 10), "/very/l...");
    }
}
