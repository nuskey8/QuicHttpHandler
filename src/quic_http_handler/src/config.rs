use std::{
    net::IpAddr,
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct EarlyDataStats {
    pub(super) attempts: AtomicU64,
    pub(super) accepted: AtomicU64,
    pub(super) rejected: AtomicU64,
}

#[derive(Clone)]
pub(super) struct ConnectionSettings {
    pub(super) connect_timeout: Duration,
    pub(super) handshake_timeout: Duration,
    pub(super) pooled_connection_idle_timeout: Option<Duration>,
    pub(super) pooled_connection_lifetime: Option<Duration>,
    pub(super) dns_timeout: Duration,
    pub(super) dns_refresh_timeout: Duration,
    pub(super) happy_eyeballs_delay: Duration,
    pub(super) keep_alive_ping_delay: Option<Duration>,
    pub(super) keep_alive_ping_timeout: Duration,
    pub(super) keep_alive_ping_while_idle: bool,
    pub(super) max_connections_per_server: usize,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            pooled_connection_idle_timeout: Some(Duration::from_secs(120)),
            pooled_connection_lifetime: None,
            dns_timeout: Duration::from_secs(5),
            dns_refresh_timeout: Duration::from_secs(60),
            happy_eyeballs_delay: Duration::from_millis(250),
            keep_alive_ping_delay: None,
            keep_alive_ping_timeout: Duration::from_secs(20),
            keep_alive_ping_while_idle: false,
            max_connections_per_server: 4,
        }
    }
}

#[derive(Clone)]
pub(super) struct Http3Configuration {
    pub(super) max_header_list_size: Option<u64>,
    pub(super) qpack_max_table_capacity: u64,
    pub(super) qpack_blocked_streams: u64,
    pub(super) enable_extended_connect: bool,
}

impl Default for Http3Configuration {
    fn default() -> Self {
        Self {
            max_header_list_size: Some(32_768),
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            enable_extended_connect: false,
        }
    }
}

#[derive(Clone)]
pub(super) struct QuicConfiguration {
    pub(super) enable_early_data: bool,
    pub(super) initial_max_data: u64,
    pub(super) initial_max_stream_data_bidi_local: u64,
    pub(super) initial_max_stream_data_bidi_remote: u64,
    pub(super) initial_max_stream_data_uni: u64,
    pub(super) initial_max_streams_bidi: u64,
    pub(super) initial_max_streams_uni: u64,
    pub(super) max_connection_window: u64,
    pub(super) max_stream_window: u64,
    pub(super) send_buffer_size: usize,
    pub(super) receive_buffer_size: usize,
    pub(super) congestion_control: u8,
    pub(super) initial_congestion_window_packets: usize,
    pub(super) enable_pacing: bool,
    pub(super) max_pacing_rate: Option<u64>,
    pub(super) discover_path_mtu: bool,
    pub(super) pmtud_max_probes: u8,
    pub(super) enable_hystart: bool,
    pub(super) max_send_udp_payload_size: usize,
    pub(super) max_receive_udp_payload_size: usize,
    pub(super) ack_delay_exponent: u64,
    pub(super) max_ack_delay: u64,
    pub(super) send_capacity_factor: f64,
}
impl Default for QuicConfiguration {
    fn default() -> Self {
        Self {
            enable_early_data: false,
            initial_max_data: 10 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 1024 * 1024,
            initial_max_stream_data_bidi_remote: 1024 * 1024,
            initial_max_stream_data_uni: 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_connection_window: 24 * 1024 * 1024,
            max_stream_window: 16 * 1024 * 1024,
            send_buffer_size: 0,
            receive_buffer_size: 0,
            congestion_control: 0,
            initial_congestion_window_packets: 10,
            enable_pacing: false,
            max_pacing_rate: None,
            discover_path_mtu: false,
            pmtud_max_probes: 3,
            enable_hystart: true,
            max_send_udp_payload_size: 1350,
            max_receive_udp_payload_size: 1350,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            send_capacity_factor: 1.0,
        }
    }
}

pub(super) struct DnsCacheEntry {
    pub(super) addresses: Vec<IpAddr>,
    pub(super) expires_at: Instant,
}
