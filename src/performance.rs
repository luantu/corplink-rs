#[allow(dead_code)]
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_duration: Duration,
    pub average_latency: Duration,
    pub dns_query_count: u64,
    pub dns_cache_hits: u64,
    pub dns_cache_misses: u64,
}

#[allow(dead_code)]
impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            connection_duration: Duration::new(0, 0),
            average_latency: Duration::new(0, 0),
            dns_query_count: 0,
            dns_cache_hits: 0,
            dns_cache_misses: 0,
        }
    }

    pub fn throughput_mbps(&self) -> f64 {
        if self.connection_duration.as_secs() == 0 {
            return 0.0;
        }
        let total_bytes = self.bytes_sent + self.bytes_received;
        let seconds = self.connection_duration.as_secs_f64();
        (total_bytes as f64 * 8.0) / (seconds * 1_000_000.0)
    }

    pub fn packets_per_second(&self) -> f64 {
        if self.connection_duration.as_secs() == 0 {
            return 0.0;
        }
        let total_packets = self.packets_sent + self.packets_received;
        let seconds = self.connection_duration.as_secs_f64();
        total_packets as f64 / seconds
    }

    pub fn dns_cache_hit_rate(&self) -> f64 {
        if self.dns_query_count == 0 {
            return 0.0;
        }
        (self.dns_cache_hits as f64 / self.dns_query_count as f64) * 100.0
    }
}

#[allow(dead_code)]
pub struct PerformanceMonitor {
    start_time: Instant,
    metrics: PerformanceMetrics,
}

#[allow(dead_code)]
impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            metrics: PerformanceMetrics::new(),
        }
    }

    pub fn record_bytes_sent(&mut self, bytes: u64) {
        self.metrics.bytes_sent += bytes;
    }

    pub fn record_bytes_received(&mut self, bytes: u64) {
        self.metrics.bytes_received += bytes;
    }

    pub fn record_packet_sent(&mut self) {
        self.metrics.packets_sent += 1;
    }

    pub fn record_packet_received(&mut self) {
        self.metrics.packets_received += 1;
    }

    pub fn record_dns_query(&mut self, cache_hit: bool) {
        self.metrics.dns_query_count += 1;
        if cache_hit {
            self.metrics.dns_cache_hits += 1;
        } else {
            self.metrics.dns_cache_misses += 1;
        }
    }

    pub fn get_metrics(&self) -> PerformanceMetrics {
        let mut metrics = self.metrics.clone();
        metrics.connection_duration = self.start_time.elapsed();
        metrics
    }

    pub fn log_performance(&self) {
        let metrics = self.get_metrics();
        log::info!("=== Performance Metrics ===");
        log::info!("Connection Duration: {:?}", metrics.connection_duration);
        log::info!("Bytes Sent: {} ({:.2} MB)", metrics.bytes_sent, metrics.bytes_sent as f64 / 1_000_000.0);
        log::info!("Bytes Received: {} ({:.2} MB)", metrics.bytes_received, metrics.bytes_received as f64 / 1_000_000.0);
        log::info!("Throughput: {:.2} Mbps", metrics.throughput_mbps());
        log::info!("Packets Sent: {}", metrics.packets_sent);
        log::info!("Packets Received: {}", metrics.packets_received);
        log::info!("Packets/Second: {:.2}", metrics.packets_per_second());
        log::info!("DNS Queries: {}", metrics.dns_query_count);
        log::info!("DNS Cache Hit Rate: {:.2}%", metrics.dns_cache_hit_rate());
        log::info!("===========================");
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}
