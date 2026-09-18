use boring::{pkey::PKey, x509::X509};
use bytes::Bytes;
use futures_util::{stream::FuturesUnordered, SinkExt, StreamExt};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::c_void,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    slice, str,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, oneshot, Notify},
    time::{sleep, sleep_until, timeout, Instant as TokioInstant},
};
use tokio_quiche::{
    http3::driver::{
        ClientH3Event, ClientRequestSender, H3ConnectionError, H3Event, InboundFrame,
        NewClientRequest, OutboundFrame, StreamShutdown,
    },
    http3::settings::Http3Settings,
    quic::QuicCommand,
    quiche::h3::{Header, NameValue},
    settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths},
    socket::Socket,
    ClientH3Driver, ConnectionParams,
};

use crate::config::{
    ConnectionSettings, DnsCacheEntry, EarlyDataStats, Http3Configuration, QuicConfiguration,
};
use crate::qlog::QlogSettings;
use crate::tls::{compute_tls_identity, origin_key, TlsHook, TlsSettings};

const BODY_CHANNEL_CAPACITY: usize = 8;
const SSL_EARLY_DATA_ACCEPTED: u32 = 2;

struct H3hCallbacks {
    on_headers: extern "C" fn(*mut c_void, u32, *const u8, usize) -> u8,
    on_body: extern "C" fn(*mut c_void, *const u8, usize) -> u8,
    on_trailers: extern "C" fn(*mut c_void, *const u8, usize) -> u8,
    on_informational_headers: extern "C" fn(*mut c_void, u32, *const u8, usize) -> u8,
    on_complete: extern "C" fn(*mut c_void, i32, i32, u64, *const u8, usize),
}

pub struct Context {
    runtime: Option<Runtime>,
    callbacks: H3hCallbacks,
    connections: Mutex<HashMap<OriginKey, Vec<ConnectionSlot>>>,
    next_request_id: AtomicU64,
    tls: Mutex<Arc<TlsSettings>>,
    connection_settings: Mutex<ConnectionSettings>,
    http3_settings: Mutex<Http3Configuration>,
    quic_settings: Mutex<QuicConfiguration>,
    dns_cache: Arc<Mutex<HashMap<String, DnsCacheEntry>>>,
    dns_overrides: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
    session_cache: Arc<Mutex<HashMap<OriginKey, Vec<u8>>>>,
    early_data_stats: Arc<EarlyDataStats>,
    qlog: Mutex<QlogSettings>,
}

pub struct Request {
    body: Mutex<Option<mpsc::Sender<BodyChunk>>>,
    life: Arc<RequestLife>,
    on_complete: extern "C" fn(*mut c_void, i32, i32, u64, *const u8, usize),
    request_id: u64,
    control: mpsc::UnboundedSender<ActorCommand>,
}
enum BodyChunk {
    Data(Bytes),
    Finish,
}

#[derive(Clone)]
struct RequestMeta {
    life: Arc<RequestLife>,
}

struct RequestLife {
    state: usize,
    cancelled: AtomicBool,
    completed: AtomicBool,
    callback_gate: Mutex<()>,
    body_resume: Notify,
    write_resume: Notify,
    pool_state: OnceLock<Arc<PoolState>>,
}

type CompletionCallback = extern "C" fn(*mut c_void, i32, i32, u64, *const u8, usize);

struct Completion<'a> {
    code: i32,
    error_kind: i32,
    protocol_code: u64,
    message: &'a str,
}

impl Completion<'_> {
    fn new(code: i32, message: &str) -> Completion<'_> {
        Completion {
            code,
            error_kind: if code == 0 { 0 } else { 3 },
            protocol_code: u64::MAX,
            message,
        }
    }

    fn stream_reset(error_code: u64, response_started: bool, message: &str) -> Completion<'_> {
        Completion {
            code: if response_started {
                2
            } else if error_code == 0x010b {
                6
            } else {
                5
            },
            error_kind: 2,
            protocol_code: error_code,
            message,
        }
    }
}

impl RequestLife {
    fn send_body_chunk(&self, sender: mpsc::Sender<BodyChunk>, chunk: BodyChunk) -> bool {
        futures_executor::block_on(async {
            let notified = self.write_resume.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::Acquire) || self.completed.load(Ordering::Acquire) {
                return false;
            }
            tokio::select! {
                result = sender.send(chunk) => result.is_ok(),
                _ = &mut notified => false,
            }
        })
    }

    fn complete(&self, callback: CompletionCallback, completion: Completion<'_>) {
        let _guard = self.callback_gate.lock().unwrap();
        if !self.completed.swap(true, Ordering::AcqRel) {
            self.write_resume.notify_waiters();
            if let Some(pool_state) = self.pool_state.get() {
                pool_state.request_finished();
            }
            callback(
                self.state as *mut c_void,
                completion.code,
                completion.error_kind,
                completion.protocol_code,
                completion.message.as_ptr(),
                completion.message.len(),
            );
        }
    }
}
struct Command {
    id: u64,
    headers: Vec<Header>,
    body: Option<mpsc::Receiver<BodyChunk>>,
    life: Arc<RequestLife>,
    allow_early_data: bool,
}

fn encode_headers(headers: &[Header]) -> Vec<u8> {
    let capacity = headers
        .iter()
        .filter(|header| !header.name().starts_with(b":"))
        .map(|header| header.name().len() + header.value().len() + 2)
        .sum();
    let mut encoded = Vec::with_capacity(capacity);
    for header in headers {
        if !header.name().starts_with(b":") {
            encoded.extend_from_slice(header.name());
            encoded.push(0);
            encoded.extend_from_slice(header.value());
            encoded.push(0);
        }
    }
    encoded
}

enum ActorCommand {
    Submit(Command),
    Cancel(u64),
    Drain,
    Shutdown,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OriginKey {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) server_name: String,
    pub(crate) tls_identity: u64,
}

#[derive(Clone)]
struct ConnectionSlot {
    sender: mpsc::UnboundedSender<ActorCommand>,
    draining: Arc<AtomicBool>,
    pool_state: Arc<PoolState>,
}

struct PoolState {
    created_at: std::time::Instant,
    active_requests: AtomicUsize,
    idle_since: Mutex<Option<std::time::Instant>>,
    accepting: AtomicBool,
    stream_capacity_blocked: AtomicBool,
    reserved_requests: AtomicUsize,
    total_requests: AtomicU64,
    changed: Notify,
}

impl PoolState {
    fn can_open_stream(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
            && !self.stream_capacity_blocked.load(Ordering::Acquire)
    }

    fn request_started(self: &Arc<Self>, life: &RequestLife) -> bool {
        if !self.accepting.load(Ordering::Acquire) {
            return false;
        }
        let was_idle = self.active_requests.fetch_add(1, Ordering::AcqRel) == 0;
        self.reserved_requests.fetch_add(1, Ordering::AcqRel);
        self.total_requests.fetch_add(1, Ordering::AcqRel);
        if was_idle {
            let mut idle_since = self.idle_since.lock().unwrap();
            if self.active_requests.load(Ordering::Acquire) != 0 {
                *idle_since = None;
            }
        }
        let _ = life.pool_state.set(self.clone());
        true
    }

    fn request_finished(&self) {
        if self.active_requests.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut idle_since = self.idle_since.lock().unwrap();
            if self.active_requests.load(Ordering::Acquire) == 0 {
                *idle_since = Some(std::time::Instant::now());
            }
        }
        self.reserved_requests.fetch_sub(1, Ordering::AcqRel);
        self.changed.notify_one();
    }
}

async fn wait_for_deadline(deadline: Option<TokioInstant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => futures_util::future::pending().await,
    }
}

const H3_REQUEST_CANCELLED: u64 = 0x010c;

unsafe impl Send for H3hCallbacks {}
unsafe impl Sync for H3hCallbacks {}

struct RawSlice<'a>(&'a [u8]);

impl<'a> RawSlice<'a> {
    unsafe fn from_raw(ptr: *const u8, len: usize) -> Result<Self, String> {
        if len == 0 {
            Ok(Self(&[]))
        } else if ptr.is_null() {
            Err("null pointer with non-zero length".to_owned())
        } else {
            Ok(Self(unsafe { slice::from_raw_parts(ptr, len) }))
        }
    }

    fn as_slice(&self) -> &'a [u8] {
        self.0
    }

    fn as_utf8(&self) -> Result<&'a str, String> {
        str::from_utf8(self.0).map_err(|error| format!("invalid UTF-8: {error}"))
    }
}

fn h3_protocol_error_details(error: &tokio_quiche::quiche::h3::Error) -> (i32, u64) {
    use tokio_quiche::quiche::h3::Error;
    let code = match error {
        Error::TransportError(_) => return (1, u64::MAX),
        Error::Done => 0x100,
        Error::InternalError => 0x102,
        Error::StreamCreationError => 0x103,
        Error::ClosedCriticalStream => 0x104,
        Error::FrameUnexpected => 0x105,
        Error::FrameError => 0x106,
        Error::ExcessiveLoad => 0x107,
        Error::IdError => 0x108,
        Error::SettingsError => 0x109,
        Error::MissingSettings => 0x10a,
        Error::RequestRejected => 0x10b,
        Error::RequestCancelled => 0x10c,
        Error::RequestIncomplete => 0x10d,
        Error::MessageError => 0x10e,
        Error::ConnectError => 0x10f,
        Error::VersionFallback => 0x110,
        Error::QpackDecompressionFailed => 0x200,
        Error::BufferTooShort | Error::StreamBlocked => u64::MAX,
    };
    (2, code)
}
#[allow(clippy::too_many_arguments)]
fn complete_actor_requests(
    by_request: &mut HashMap<u64, RequestMeta>,
    by_stream: &mut HashMap<u64, RequestMeta>,
    pending: &mut VecDeque<Command>,
    stream_by_request: &mut HashMap<u64, u64>,
    finish_by_stream: &mut HashMap<u64, oneshot::Sender<()>>,
    cancelled_requests: &mut HashSet<u64>,
    callback: extern "C" fn(*mut c_void, i32, i32, u64, *const u8, usize),
    code: i32,
    error_kind: i32,
    protocol_code: u64,
    message: &str,
) {
    finish_by_stream.clear();
    stream_by_request.clear();
    cancelled_requests.clear();
    for (_, meta) in by_request.drain().chain(by_stream.drain()) {
        meta.life.complete(
            callback,
            Completion {
                code,
                error_kind,
                protocol_code,
                message,
            },
        );
    }
    while let Some(command) = pending.pop_front() {
        command.life.complete(
            callback,
            Completion {
                code,
                error_kind,
                protocol_code,
                message,
            },
        );
    }
}

#[no_mangle]
pub extern "C" fn qhh_context_new(
    worker_threads: i32,
    on_headers: extern "C" fn(*mut c_void, u32, *const u8, usize) -> u8,
    on_body: extern "C" fn(*mut c_void, *const u8, usize) -> u8,
    on_trailers: extern "C" fn(*mut c_void, *const u8, usize) -> u8,
    on_informational_headers: extern "C" fn(*mut c_void, u32, *const u8, usize) -> u8,
    on_complete: extern "C" fn(*mut c_void, i32, i32, u64, *const u8, usize),
) -> *mut Context {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().thread_name("quic-http-handler");
    if worker_threads > 0 {
        builder.worker_threads(worker_threads as usize);
    }
    builder
        .build()
        .map(|runtime| {
            Box::into_raw(Box::new(Context {
                runtime: Some(runtime),
                callbacks: H3hCallbacks {
                    on_headers,
                    on_body,
                    on_trailers,
                    on_informational_headers,
                    on_complete,
                },
                connections: Mutex::new(HashMap::new()),
                next_request_id: AtomicU64::new(1),
                tls: Mutex::new(Arc::new(TlsSettings::default())),
                connection_settings: Mutex::new(ConnectionSettings::default()),
                http3_settings: Mutex::new(Http3Configuration::default()),
                quic_settings: Mutex::new(QuicConfiguration::default()),
                dns_cache: Arc::new(Mutex::new(HashMap::new())),
                dns_overrides: Arc::new(Mutex::new(HashMap::new())),
                session_cache: Arc::new(Mutex::new(HashMap::new())),
                early_data_stats: Arc::new(EarlyDataStats::default()),
                qlog: Mutex::new(QlogSettings::default()),
            }))
        })
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_connection_options(
    context: *mut Context,
    connect_timeout_ms: u64,
    handshake_timeout_ms: u64,
    pooled_connection_idle_timeout_ms: u64,
    pooled_connection_lifetime_ms: u64,
    dns_timeout_ms: u64,
    dns_refresh_timeout_ms: u64,
    happy_eyeballs_delay_ms: u64,
    keep_alive_ping_delay_ms: u64,
    keep_alive_ping_timeout_ms: u64,
    keep_alive_ping_while_idle: bool,
    max_connections_per_server: usize,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    if connect_timeout_ms == 0
        || handshake_timeout_ms == 0
        || dns_timeout_ms == 0
        || dns_refresh_timeout_ms == 0
        || keep_alive_ping_delay_ms == 0
        || keep_alive_ping_timeout_ms == 0
        || keep_alive_ping_timeout_ms == u64::MAX
        || max_connections_per_server == 0
    {
        return false;
    }
    let optional = |value| (value != u64::MAX).then(|| std::time::Duration::from_millis(value));
    *context.connection_settings.lock().unwrap() = ConnectionSettings {
        connect_timeout: std::time::Duration::from_millis(connect_timeout_ms),
        handshake_timeout: std::time::Duration::from_millis(handshake_timeout_ms),
        pooled_connection_idle_timeout: optional(pooled_connection_idle_timeout_ms),
        pooled_connection_lifetime: optional(pooled_connection_lifetime_ms),
        dns_timeout: std::time::Duration::from_millis(dns_timeout_ms),
        dns_refresh_timeout: std::time::Duration::from_millis(dns_refresh_timeout_ms),
        happy_eyeballs_delay: std::time::Duration::from_millis(happy_eyeballs_delay_ms),
        keep_alive_ping_delay: optional(keep_alive_ping_delay_ms),
        keep_alive_ping_timeout: std::time::Duration::from_millis(keep_alive_ping_timeout_ms),
        keep_alive_ping_while_idle,
        max_connections_per_server,
    };
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_dns_override(
    context: *mut Context,
    host_ptr: *const u8,
    host_len: usize,
    addresses_ptr: *const u8,
    addresses_len: usize,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    let Ok(host) = RawSlice::from_raw(host_ptr, host_len).and_then(|value| value.as_utf8()) else {
        return false;
    };
    let Ok(addresses) =
        RawSlice::from_raw(addresses_ptr, addresses_len).and_then(|value| value.as_utf8())
    else {
        return false;
    };
    let addresses = addresses
        .split(',')
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(addresses) = addresses else {
        return false;
    };
    if host.is_empty() || addresses.is_empty() {
        return false;
    }
    context
        .dns_overrides
        .lock()
        .unwrap()
        .insert(host.to_ascii_lowercase(), addresses);
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_qlog(
    context: *mut Context,
    state: *mut c_void,
    callback: Option<extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> u8>,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    *context.qlog.lock().unwrap() = QlogSettings {
        state: state as usize,
        callback,
    };
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_http3_options(
    context: *mut Context,
    max_header_list_size: u64,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
    enable_extended_connect: bool,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    *context.http3_settings.lock().unwrap() = Http3Configuration {
        max_header_list_size: (max_header_list_size != u64::MAX).then_some(max_header_list_size),
        qpack_max_table_capacity,
        qpack_blocked_streams,
        enable_extended_connect,
    };
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_quic_flow_control(
    context: *mut Context,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    max_connection_window: u64,
    max_stream_window: u64,
    send_buffer_size: usize,
    receive_buffer_size: usize,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    if initial_max_data == 0
        || initial_max_stream_data_bidi_local == 0
        || initial_max_stream_data_bidi_remote == 0
        || initial_max_stream_data_uni == 0
        || initial_max_streams_bidi == 0
        || initial_max_streams_uni == 0
        || max_connection_window < initial_max_data
        || max_stream_window
            < initial_max_stream_data_bidi_local
                .max(initial_max_stream_data_bidi_remote)
                .max(initial_max_stream_data_uni)
    {
        return false;
    }
    let mut settings = context.quic_settings.lock().unwrap();
    settings.initial_max_data = initial_max_data;
    settings.initial_max_stream_data_bidi_local = initial_max_stream_data_bidi_local;
    settings.initial_max_stream_data_bidi_remote = initial_max_stream_data_bidi_remote;
    settings.initial_max_stream_data_uni = initial_max_stream_data_uni;
    settings.initial_max_streams_bidi = initial_max_streams_bidi;
    settings.initial_max_streams_uni = initial_max_streams_uni;
    settings.max_connection_window = max_connection_window;
    settings.max_stream_window = max_stream_window;
    settings.send_buffer_size = send_buffer_size;
    settings.receive_buffer_size = receive_buffer_size;
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_quic_performance(
    context: *mut Context,
    congestion_control: u8,
    initial_congestion_window_packets: usize,
    enable_pacing: bool,
    max_pacing_rate: u64,
    discover_path_mtu: bool,
    pmtud_max_probes: u8,
    enable_hystart: bool,
    max_send_udp_payload_size: usize,
    max_receive_udp_payload_size: usize,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    send_capacity_factor: f64,
    enable_early_data: bool,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    if congestion_control > 2
        || initial_congestion_window_packets == 0
        || pmtud_max_probes == 0
        || max_send_udp_payload_size < 1200
        || max_receive_udp_payload_size < 1200
        || ack_delay_exponent > 20
        || !send_capacity_factor.is_finite()
        || send_capacity_factor <= 0.0
    {
        return false;
    }
    let mut settings = context.quic_settings.lock().unwrap();
    settings.congestion_control = congestion_control;
    settings.initial_congestion_window_packets = initial_congestion_window_packets;
    settings.enable_pacing = enable_pacing;
    settings.max_pacing_rate = (max_pacing_rate != 0).then_some(max_pacing_rate);
    settings.discover_path_mtu = discover_path_mtu;
    settings.pmtud_max_probes = pmtud_max_probes;
    settings.enable_hystart = enable_hystart;
    settings.max_send_udp_payload_size = max_send_udp_payload_size;
    settings.max_receive_udp_payload_size = max_receive_udp_payload_size;
    settings.ack_delay_exponent = ack_delay_exponent;
    settings.max_ack_delay = max_ack_delay;
    settings.send_capacity_factor = send_capacity_factor;
    settings.enable_early_data = enable_early_data;
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_set_tls_options(
    context: *mut Context,
    skip_verification: bool,
    custom_verify: bool,
    replace_default_roots: bool,
    override_name: *const u8,
    override_name_len: usize,
    roots: *const u8,
    roots_len: usize,
    client_certificates: *const u8,
    client_certificates_len: usize,
    client_key: *const u8,
    client_key_len: usize,
    verify_state: *mut c_void,
    verify_callback: Option<
        extern "C" fn(
            *mut c_void,
            *const u8,
            usize,
            *const u8,
            usize,
            *const u8,
            usize,
            u8,
            i32,
            i64,
        ) -> u8,
    >,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    let override_server_name = if override_name_len == 0 {
        None
    } else {
        match RawSlice::from_raw(override_name, override_name_len).and_then(|value| value.as_utf8())
        {
            Ok(value) => Some(value.to_owned()),
            Err(_) => return false,
        }
    };
    let Ok(root_certificates) = RawSlice::from_raw(roots, roots_len) else {
        return false;
    };
    let Ok(client_certificates) = RawSlice::from_raw(client_certificates, client_certificates_len)
    else {
        return false;
    };
    let Ok(client_key) = RawSlice::from_raw(client_key, client_key_len) else {
        return false;
    };
    let root_certificates = root_certificates.as_slice().to_vec();
    let client_certificates = client_certificates.as_slice().to_vec();
    let client_key = client_key.as_slice().to_vec();
    if !root_certificates.is_empty()
        && X509::stack_from_pem(&root_certificates).map_or(true, |values| values.is_empty())
    {
        return false;
    }
    if client_certificates.is_empty() != client_key.is_empty() {
        return false;
    }
    if !client_certificates.is_empty() {
        let Ok(certificates) = X509::stack_from_pem(&client_certificates) else {
            return false;
        };
        let Ok(key) = PKey::private_key_from_pem(&client_key) else {
            return false;
        };
        if certificates.is_empty()
            || certificates[0]
                .public_key()
                .map_or(true, |public_key| !public_key.public_eq(&key))
        {
            return false;
        }
    }
    let mut settings = TlsSettings {
        identity: 0,
        skip_verification,
        custom_verify,
        replace_default_roots,
        override_server_name,
        root_certificates,
        client_certificates,
        client_key,
        verify_state: verify_state as usize,
        verify_callback,
    };
    settings.identity = compute_tls_identity(&settings);
    *context.tls.lock().unwrap() = Arc::new(settings);
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_dispose(context: *mut Context) {
    if !context.is_null() {
        let mut context = Box::from_raw(context);
        {
            let pool = context.connections.lock().unwrap();
            for slot in pool.values().flatten() {
                slot.pool_state.accepting.store(false, Ordering::Release);
                let _ = slot.sender.send(ActorCommand::Shutdown);
            }
        }
        if let Some(runtime) = context.runtime.take() {
            runtime.shutdown_timeout(std::time::Duration::from_secs(1));
        }
        context.connections.lock().unwrap().clear();
    }
}

#[no_mangle]
pub unsafe extern "C" fn qhh_context_get_pool_statistics(
    context: *mut Context,
    connections: *mut usize,
    accepting_connections: *mut usize,
    idle_connections: *mut usize,
    active_requests: *mut usize,
    total_requests: *mut u64,
    early_data_attempts: *mut u64,
    early_data_accepted: *mut u64,
    early_data_rejected: *mut u64,
) -> bool {
    let Some(context) = context.as_ref() else {
        return false;
    };
    if connections.is_null()
        || accepting_connections.is_null()
        || idle_connections.is_null()
        || active_requests.is_null()
        || total_requests.is_null()
        || early_data_attempts.is_null()
        || early_data_accepted.is_null()
        || early_data_rejected.is_null()
    {
        return false;
    }
    let mut pool = context.connections.lock().unwrap();
    pool.retain(|_, slots| {
        slots.retain(|slot| !slot.sender.is_closed());
        !slots.is_empty()
    });
    let slots = pool.values().flatten();
    let mut values = (0usize, 0usize, 0usize, 0usize, 0u64);
    for slot in slots {
        values.0 += 1;
        values.1 += usize::from(slot.pool_state.accepting.load(Ordering::Acquire));
        values.2 += usize::from(slot.pool_state.active_requests.load(Ordering::Acquire) == 0);
        values.3 += slot.pool_state.active_requests.load(Ordering::Acquire);
        values.4 += slot.pool_state.total_requests.load(Ordering::Acquire);
    }
    *connections = values.0;
    *accepting_connections = values.1;
    *idle_connections = values.2;
    *active_requests = values.3;
    *total_requests = values.4;
    *early_data_attempts = context.early_data_stats.attempts.load(Ordering::Acquire);
    *early_data_accepted = context.early_data_stats.accepted.load(Ordering::Acquire);
    *early_data_rejected = context.early_data_stats.rejected.load(Ordering::Acquire);
    true
}

#[no_mangle]
pub unsafe extern "C" fn qhh_send(
    context: *mut Context,
    state: *mut c_void,
    method_ptr: *const u8,
    method_len: usize,
    host_ptr: *const u8,
    host_len: usize,
    port: u16,
    authority_ptr: *const u8,
    authority_len: usize,
    path_ptr: *const u8,
    path_len: usize,
    headers_ptr: *const u8,
    headers_len: usize,
    has_body: bool,
    allow_early_data: bool,
) -> *mut Request {
    let Some(context) = context.as_ref() else {
        return std::ptr::null_mut();
    };
    let fail = |message: String| {
        (context.callbacks.on_complete)(state, 1, 3, u64::MAX, message.as_ptr(), message.len());
        std::ptr::null_mut()
    };
    let method = match RawSlice::from_raw(method_ptr, method_len).and_then(|value| value.as_utf8())
    {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let host = match RawSlice::from_raw(host_ptr, host_len).and_then(|value| value.as_utf8()) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return fail("URL has no host".into()),
        Err(e) => return fail(e),
    };
    let authority = match RawSlice::from_raw(authority_ptr, authority_len) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let path = match RawSlice::from_raw(path_ptr, path_len) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let encoded_headers = match RawSlice::from_raw(headers_ptr, headers_len) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let tls = context.tls.lock().unwrap().clone();
    let origin = origin_key(host, port, &tls);
    let mut headers = vec![
        Header::new(b":method", method.as_bytes()),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", authority.as_slice()),
        Header::new(b":path", path.as_slice()),
    ];
    let mut parts = encoded_headers.as_slice().split(|b| *b == 0);
    while let (Some(name), Some(value)) = (parts.next(), parts.next()) {
        if !name.is_empty() && name[0] != b':' {
            headers.push(Header::new(name, value));
        }
    }

    let (body_tx, body_rx) = if has_body {
        let (tx, rx) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let life = Arc::new(RequestLife {
        state: state as usize,
        cancelled: AtomicBool::new(false),
        completed: AtomicBool::new(false),
        callback_gate: Mutex::new(()),
        body_resume: Notify::new(),
        write_resume: Notify::new(),
        pool_state: OnceLock::new(),
    });
    let id = context.next_request_id.fetch_add(1, Ordering::Relaxed);
    let command = Command {
        id,
        headers,
        body: body_rx,
        life: life.clone(),
        allow_early_data,
    };
    let sender = {
        let mut pool = context.connections.lock().unwrap();
        let settings = context.connection_settings.lock().unwrap().clone();
        let now = std::time::Instant::now();
        let slots = pool.entry(origin.clone()).or_default();
        for slot in slots.iter() {
            let expired = {
                let idle_expired = settings
                    .pooled_connection_idle_timeout
                    .is_some_and(|limit| {
                        slot.pool_state.active_requests.load(Ordering::Acquire) == 0
                            && slot.pool_state.idle_since.lock().unwrap().is_some_and(
                                |idle_since| {
                                    slot.pool_state.active_requests.load(Ordering::Acquire) == 0
                                        && now.duration_since(idle_since) >= limit
                                },
                            )
                    });
                let lifetime_expired = settings
                    .pooled_connection_lifetime
                    .is_some_and(|limit| now.duration_since(slot.pool_state.created_at) >= limit);
                slot.sender.is_closed() || idle_expired || lifetime_expired
            };
            if expired {
                slot.pool_state.accepting.store(false, Ordering::Release);
                slot.draining.store(true, Ordering::Release);
                let _ = slot.sender.send(ActorCommand::Drain);
            }
        }
        let accepting_count = slots
            .iter()
            .filter(|slot| {
                !slot.sender.is_closed() && slot.pool_state.accepting.load(Ordering::Acquire)
            })
            .count();
        let preferred = slots
            .iter()
            .filter(|slot| slot.pool_state.can_open_stream())
            .min_by_key(|slot| slot.pool_state.reserved_requests.load(Ordering::Acquire))
            .cloned();
        let fallback = || {
            slots
                .iter()
                .filter(|slot| {
                    !slot.sender.is_closed() && slot.pool_state.accepting.load(Ordering::Acquire)
                })
                .min_by_key(|slot| slot.pool_state.reserved_requests.load(Ordering::Acquire))
                .cloned()
        };
        if let Some(slot) = preferred.or_else(|| {
            (accepting_count >= settings.max_connections_per_server)
                .then(fallback)
                .flatten()
        }) {
            let reserved = slot.pool_state.request_started(&life);
            debug_assert!(reserved);
            slot.sender
        } else {
            let (tx, rx) = mpsc::unbounded_channel();
            let draining = Arc::new(AtomicBool::new(false));
            let pool_state = Arc::new(PoolState {
                created_at: now,
                active_requests: AtomicUsize::new(0),
                idle_since: Mutex::new(Some(now)),
                accepting: AtomicBool::new(true),
                stream_capacity_blocked: AtomicBool::new(false),
                reserved_requests: AtomicUsize::new(0),
                total_requests: AtomicU64::new(0),
                changed: Notify::new(),
            });
            let reserved = pool_state.request_started(&life);
            debug_assert!(reserved);
            slots.push(ConnectionSlot {
                sender: tx.clone(),
                draining: draining.clone(),
                pool_state: pool_state.clone(),
            });
            let callbacks = H3hCallbacks {
                on_headers: context.callbacks.on_headers,
                on_body: context.callbacks.on_body,
                on_trailers: context.callbacks.on_trailers,
                on_informational_headers: context.callbacks.on_informational_headers,
                on_complete: context.callbacks.on_complete,
            };
            let dns_cache = context.dns_cache.clone();
            let dns_overrides = context.dns_overrides.clone();
            let session_cache = context.session_cache.clone();
            let early_data_stats = context.early_data_stats.clone();
            let http3_settings = context.http3_settings.lock().unwrap().clone();
            let quic_settings = context.quic_settings.lock().unwrap().clone();
            let qlog = context.qlog.lock().unwrap().clone();
            let qlog = qlog.callback.map(|_| qlog);
            context.runtime.as_ref().unwrap().spawn(connection_actor(
                host.to_owned(),
                port,
                rx,
                callbacks,
                tls,
                draining,
                settings,
                dns_cache,
                dns_overrides,
                session_cache,
                early_data_stats,
                origin,
                pool_state,
                qlog,
                http3_settings,
                quic_settings,
            ));
            tx
        }
    };
    if let Err(error) = sender.send(ActorCommand::Submit(command)) {
        if let ActorCommand::Submit(command) = error.0 {
            command.life.complete(
                context.callbacks.on_complete,
                Completion::new(1, "HTTP/3 connection actor stopped"),
            );
        }
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(Request {
        body: Mutex::new(body_tx),
        life,
        on_complete: context.callbacks.on_complete,
        request_id: id,
        control: sender,
    }))
}

#[no_mangle]
pub unsafe extern "C" fn qhh_request_write(
    request: *mut Request,
    data: *const u8,
    len: usize,
) -> bool {
    let Some(request) = request.as_ref() else {
        return false;
    };
    if request.life.cancelled.load(Ordering::Acquire) {
        return false;
    }
    let Ok(data) = RawSlice::from_raw(data, len) else {
        return false;
    };
    let sender = request.body.lock().unwrap().clone();
    sender.is_some_and(|sender| {
        request.life.send_body_chunk(
            sender,
            BodyChunk::Data(Bytes::copy_from_slice(data.as_slice())),
        )
    })
}
#[no_mangle]
pub unsafe extern "C" fn qhh_request_finish(request: *mut Request) {
    if let Some(request) = request.as_ref() {
        if let Some(tx) = request.body.lock().unwrap().take() {
            let _ = request.life.send_body_chunk(tx, BodyChunk::Finish);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn qhh_request_cancel(request: *mut Request) {
    let values = request.as_ref().map(|request| {
        request.life.cancelled.store(true, Ordering::Release);
        request.life.write_resume.notify_waiters();
        request.life.body_resume.notify_one();
        request.body.lock().unwrap().take();
        let _ = request
            .control
            .send(ActorCommand::Cancel(request.request_id));
        (request.life.clone(), request.on_complete)
    });
    if let Some((life, on_complete)) = values {
        life.complete(on_complete, Completion::new(3, "HTTP/3 request cancelled"));
    }
}

#[no_mangle]
pub unsafe extern "C" fn qhh_request_resume_body(request: *mut Request) {
    if let Some(request) = request.as_ref() {
        request.life.body_resume.notify_one();
    }
}
#[no_mangle]
pub unsafe extern "C" fn qhh_request_dispose(request: *mut Request) {
    if !request.is_null() {
        drop(Box::from_raw(request));
    }
}

fn happy_eyeballs_order(addresses: &[IpAddr]) -> Vec<IpAddr> {
    let mut v4 = addresses.iter().copied().filter(IpAddr::is_ipv4);
    let mut v6 = addresses.iter().copied().filter(IpAddr::is_ipv6);
    let ipv6_first = addresses.first().is_some_and(IpAddr::is_ipv6);
    let mut ordered = Vec::with_capacity(addresses.len());
    loop {
        let pair = if ipv6_first {
            (v6.next(), v4.next())
        } else {
            (v4.next(), v6.next())
        };
        if pair.0.is_none() && pair.1.is_none() {
            break;
        }
        if let Some(value) = pair.0 {
            ordered.push(value);
        }
        if let Some(value) = pair.1 {
            ordered.push(value);
        }
    }
    ordered
}

fn submit_to_driver(
    command: Command,
    request_sender: &ClientRequestSender,
    by_request: &mut HashMap<u64, RequestMeta>,
) -> Result<(), std::io::Error> {
    let Command {
        id,
        headers,
        body,
        life,
        allow_early_data: _,
    } = command;
    let (writer_tx, writer_rx) = if body.is_some() {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    by_request.insert(id, RequestMeta { life });
    request_sender
        .send(NewClientRequest {
            request_id: id,
            headers,
            body_writer: writer_tx,
        })
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if let (Some(mut body), Some(writer_rx)) = (body, writer_rx) {
        tokio::spawn(async move {
            let Ok(mut writer) = writer_rx.await else {
                return;
            };
            while let Some(chunk) = body.recv().await {
                match chunk {
                    BodyChunk::Data(data) => {
                        if writer.send(OutboundFrame::Body(data, false)).await.is_err() {
                            break;
                        }
                    }
                    BodyChunk::Finish => {
                        let _ = writer.send(OutboundFrame::Body(Bytes::new(), true)).await;
                        break;
                    }
                }
            }
        });
    }
    Ok(())
}

async fn connection_actor(
    host: String,
    port: u16,
    mut commands: mpsc::UnboundedReceiver<ActorCommand>,
    callbacks: H3hCallbacks,
    tls: Arc<TlsSettings>,
    draining: Arc<AtomicBool>,
    connection_settings: ConnectionSettings,
    dns_cache: Arc<Mutex<HashMap<String, DnsCacheEntry>>>,
    dns_overrides: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
    session_cache: Arc<Mutex<HashMap<OriginKey, Vec<u8>>>>,
    early_data_stats: Arc<EarlyDataStats>,
    origin: OriginKey,
    pool_state: Arc<PoolState>,
    qlog: Option<QlogSettings>,
    http3_configuration: Http3Configuration,
    quic_configuration: QuicConfiguration,
) {
    let result = async {
        let server_name = tls.override_server_name.clone().unwrap_or_else(|| host.clone());
        let overridden = dns_overrides
            .lock()
            .unwrap()
            .get(&host.to_ascii_lowercase())
            .cloned();
        let cached = {
            let now = std::time::Instant::now();
            let mut cache = dns_cache.lock().unwrap();
            cache.retain(|_, entry| entry.expires_at > now);
            cache.get(&host).map(|entry| entry.addresses.clone())
        };
        let addresses = if let Some(addresses) = overridden {
            addresses
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else if let Some(addresses) = cached {
            addresses
        } else {
            let resolved = timeout(
                connection_settings.dns_timeout,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS lookup timed out"))??
            .map(|address| address.ip())
            .collect::<Vec<_>>();
            if resolved.is_empty() {
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "host not found"));
            }
            dns_cache.lock().unwrap().insert(host.clone(), DnsCacheEntry {
                addresses: resolved.clone(),
                expires_at: std::time::Instant::now() + connection_settings.dns_refresh_timeout,
            });
            resolved
        };
        let ordered = happy_eyeballs_order(&addresses);
        let attempts = ordered.into_iter().enumerate().map(|(index, ip)| {
            let tls = tls.clone();
            let server_name = server_name.clone();
            let settings = connection_settings.clone();
            let qlog = qlog.clone();
            let http3_configuration = http3_configuration.clone();
            let quic_configuration = quic_configuration.clone();
            let session_cache = session_cache.clone();
            let origin = origin.clone();
            async move {
                if index != 0 { sleep(settings.happy_eyeballs_delay * index as u32).await; }
                let peer = SocketAddr::new(ip, port);
                let bind = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let socket = tokio::net::UdpSocket::bind(bind).await?;
                if quic_configuration.send_buffer_size != 0 {
                    socket2::SockRef::from(&socket).set_send_buffer_size(quic_configuration.send_buffer_size)?;
                }
                if quic_configuration.receive_buffer_size != 0 {
                    socket2::SockRef::from(&socket).set_recv_buffer_size(quic_configuration.receive_buffer_size)?;
                }
                socket.connect(peer).await?;
                let socket = Socket::try_from(socket).map_err(|e| std::io::Error::other(e.to_string()))?;
                let mut quic = QuicSettings::default();
                quic.verify_peer = !tls.skip_verification;
                quic.enable_dgram = false;
                quic.handshake_timeout = Some(settings.handshake_timeout);
                quic.max_idle_timeout = settings.pooled_connection_idle_timeout;
                quic.initial_max_data = quic_configuration.initial_max_data;
                quic.initial_max_stream_data_bidi_local = quic_configuration.initial_max_stream_data_bidi_local;
                quic.initial_max_stream_data_bidi_remote = quic_configuration.initial_max_stream_data_bidi_remote;
                quic.initial_max_stream_data_uni = quic_configuration.initial_max_stream_data_uni;
                quic.initial_max_streams_bidi = quic_configuration.initial_max_streams_bidi;
                quic.initial_max_streams_uni = quic_configuration.initial_max_streams_uni;
                quic.max_connection_window = quic_configuration.max_connection_window;
                quic.max_stream_window = quic_configuration.max_stream_window;
                quic.cc_algorithm = match quic_configuration.congestion_control { 1 => "reno", 2 => "bbr2_gcongestion", _ => "cubic" }.to_owned();
                quic.initial_congestion_window_packets = quic_configuration.initial_congestion_window_packets;
                quic.enable_pacing = quic_configuration.enable_pacing;
                quic.max_pacing_rate = quic_configuration.max_pacing_rate;
                quic.discover_path_mtu = quic_configuration.discover_path_mtu;
                quic.pmtud_max_probes = quic_configuration.pmtud_max_probes;
                quic.enable_hystart = quic_configuration.enable_hystart;
                quic.max_send_udp_payload_size = quic_configuration.max_send_udp_payload_size;
                quic.max_recv_udp_payload_size = quic_configuration.max_receive_udp_payload_size;
                quic.ack_delay_exponent = quic_configuration.ack_delay_exponent;
                quic.max_ack_delay = quic_configuration.max_ack_delay;
                quic.send_capacity_factor = quic_configuration.send_capacity_factor;
                quic.enable_early_data = quic_configuration.enable_early_data;
                let hook = TlsHook { settings: tls, server_name: server_name.clone(), qlog };
                let mut hooks = Hooks::default();
                hooks.connection_hook = Some(Arc::new(hook));
                let marker = TlsCertificatePaths { cert: "unused", private_key: "unused", kind: CertificateKind::X509 };
                let mut params = ConnectionParams::new_client(quic, Some(marker), hooks);
                params.session = session_cache.lock().unwrap().get(&origin).cloned();
                let attempting_early_data =
                    quic_configuration.enable_early_data && params.session.is_some();
                let (driver, controller) = ClientH3Driver::new(Http3Settings {
                    max_header_list_size: http3_configuration.max_header_list_size,
                    qpack_max_table_capacity: Some(http3_configuration.qpack_max_table_capacity),
                    qpack_blocked_streams: Some(http3_configuration.qpack_blocked_streams),
                    enable_extended_connect: http3_configuration.enable_extended_connect,
                    ..Http3Settings::default()
                });
                let connection = timeout(
                    settings.handshake_timeout,
                    tokio_quiche::quic::connect_with_config(socket, Some(&server_name), &params, driver),
                )
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("QUIC handshake with {peer} timed out")))?
                .map_err(|e| std::io::Error::other(format!("TLS/QUIC handshake with {peer} failed: {e}")))?;
                Ok::<_, std::io::Error>((connection, controller, attempting_early_data))
            }
        }).collect::<FuturesUnordered<_>>();
        let connect = async {
            let mut attempts = attempts;
            let mut last_error = None;
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(value) => return Ok(value),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "host has no usable addresses")))
        };
        let (connection, mut controller, mut in_early_data) = timeout(connection_settings.connect_timeout, connect)
            .await.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP/3 connect timed out"))??;
        let connection_stats = connection.stats().clone();
        let _connection = connection;
        let request_sender = controller.request_sender();
        let handshake_established = Arc::new(AtomicBool::new(false));
        let early_data_outcome_recorded = Arc::new(AtomicBool::new(false));
        let early_data_was_sent = Arc::new(AtomicBool::new(false));
        let mut next_handshake_check = in_early_data
            .then(|| TokioInstant::now() + std::time::Duration::from_millis(1));
        let mut by_request = HashMap::<u64, RequestMeta>::new();
        let mut by_stream = HashMap::<u64, RequestMeta>::new();
        let mut stream_by_request = HashMap::<u64, u64>::new();
        let mut finish_by_stream = HashMap::<u64, oneshot::Sender<()>>::new();
        let mut cancelled_requests = HashSet::<u64>::new();
        let mut pending = VecDeque::<Command>::new();
        let mut has_received_request = false;
        let session_stored = Arc::new(AtomicBool::new(false));
        let mut next_session_check =
            Some(TokioInstant::now() + std::time::Duration::from_millis(1));
        let mut next_keep_alive = connection_settings
            .keep_alive_ping_delay
            .map(|interval| TokioInstant::now() + interval);
        let mut keep_alive_timeout = None;
        let mut keep_alive_recv_baseline = 0;
        loop {
            let idle_deadline = connection_settings.pooled_connection_idle_timeout.and_then(|limit| {
                pool_state.idle_since.lock().unwrap().map(|idle_since| {
                    TokioInstant::from_std(idle_since + limit)
                })
            });
            let lifetime_deadline = connection_settings
                .pooled_connection_lifetime
                .filter(|_| has_received_request)
                .map(|limit| TokioInstant::from_std(pool_state.created_at + limit));
            tokio::select! {
                _ = wait_for_deadline(next_session_check) => {
                    let session_stored = session_stored.clone();
                    let session_cache = session_cache.clone();
                    let origin = origin.clone();
                    let _ = controller.cmd_sender().send(QuicCommand::Custom(Box::new(move |connection| {
                        if let Some(session) = connection.session() {
                            session_cache.lock().unwrap().insert(origin, session.to_vec());
                            session_stored.store(true, Ordering::Release);
                        }
                    })));
                    next_session_check = Some(TokioInstant::now() + std::time::Duration::from_millis(1));
                },
                _ = wait_for_deadline(next_handshake_check) => {
                    let state = handshake_established.clone();
                    let outcome_recorded = early_data_outcome_recorded.clone();
                    let stats = early_data_stats.clone();
                    let was_sent = early_data_was_sent.clone();
                    let session_cache = session_cache.clone();
                    let origin = origin.clone();
                    let _ = controller.cmd_sender().send(QuicCommand::Custom(Box::new(move |connection| {
                        let established = connection.is_established();
                        if established
                            && was_sent.load(Ordering::Acquire)
                            && !outcome_recorded.swap(true, Ordering::AcqRel)
                        {
                            if connection.early_data_reason() == SSL_EARLY_DATA_ACCEPTED {
                                stats.accepted.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats.rejected.fetch_add(1, Ordering::Relaxed);
                                session_cache.lock().unwrap().remove(&origin);
                            }
                        }
                        state.store(established, Ordering::Release);
                    })));
                    next_handshake_check = Some(TokioInstant::now() + std::time::Duration::from_millis(1));
                },
                _ = wait_for_deadline(idle_deadline) => {
                    draining.store(true, Ordering::Release);
                    pool_state.accepting.store(false, Ordering::Release);
                },
                _ = wait_for_deadline(lifetime_deadline) => {
                    draining.store(true, Ordering::Release);
                    pool_state.accepting.store(false, Ordering::Release);
                },
                _ = wait_for_deadline(next_keep_alive) => {
                    let interval = connection_settings.keep_alive_ping_delay.unwrap();
                    next_keep_alive = Some(TokioInstant::now() + interval);
                    let should_ping = connection_settings.keep_alive_ping_while_idle
                        || pool_state.active_requests.load(Ordering::Acquire) != 0;
                    if should_ping && keep_alive_timeout.is_none() {
                        keep_alive_recv_baseline = connection_stats.lock().unwrap().stats.recv;
                        let _ = controller.cmd_sender().send(QuicCommand::Custom(Box::new(|connection| {
                            let _ = connection.send_ack_eliciting();
                        })));
                        keep_alive_timeout = Some(TokioInstant::now() + connection_settings.keep_alive_ping_timeout);
                    }
                },
                _ = wait_for_deadline(keep_alive_timeout) => {
                    keep_alive_timeout = None;
                    let received = connection_stats.lock().unwrap().stats.recv;
                    if received <= keep_alive_recv_baseline {
                        draining.store(true, Ordering::Release);
                        pool_state.accepting.store(false, Ordering::Release);
                        let _ = controller.cmd_sender().send(QuicCommand::Custom(Box::new(|connection| {
                            let _ = connection.close(false, 0, b"keep-alive timeout");
                        })));
                    }
                },
                _ = pool_state.changed.notified() => {},
                Some(actor_command) = commands.recv() => match actor_command {
                ActorCommand::Submit(command) => {
                    has_received_request = true;
                    if command.life.cancelled.load(Ordering::Acquire) { continue; }
                    if draining.load(Ordering::Acquire) {
                        command.life.complete(callbacks.on_complete, Completion::new(4, "HTTP/3 request was not processed because the connection is draining"));
                        continue;
                    }
                    pending.push_back(command);
                },
                ActorCommand::Cancel(request_id) => {
                    if let Some(stream_id) = stream_by_request.remove(&request_id) {
                        controller.shutdown_stream(stream_id, StreamShutdown::Both {
                            read_error_code: H3_REQUEST_CANCELLED,
                            write_error_code: H3_REQUEST_CANCELLED,
                        });
                        by_stream.remove(&stream_id);
                        finish_by_stream.remove(&stream_id);
                    } else if by_request.remove(&request_id).is_some() {
                        // The request has entered the tokio-quiche command queue,
                        // but a QUIC stream ID has not been assigned yet.
                        cancelled_requests.insert(request_id);
                    } else if let Some(index) = pending.iter().position(|command| command.id == request_id) {
                        pending.remove(index);
                    }
                },
                ActorCommand::Drain => {
                    draining.store(true, Ordering::Release);
                    pool_state.accepting.store(false, Ordering::Release);
                    while let Some(command) = pending.pop_front() {
                        command.life.complete(callbacks.on_complete, Completion::new(4, "HTTP/3 request was not processed because the connection is draining"));
                    }
                },
                ActorCommand::Shutdown => {
                    draining.store(true, Ordering::Release);
                    pool_state.accepting.store(false, Ordering::Release);
                    complete_actor_requests(&mut by_request, &mut by_stream, &mut pending, &mut stream_by_request, &mut finish_by_stream, &mut cancelled_requests, callbacks.on_complete, 3, 3, u64::MAX, "HTTP/3 handler was disposed");
                    return Ok(());
                },
                },
                Some(event) = controller.event_receiver_mut().recv() => match event {
                    ClientH3Event::NewOutboundRequest { stream_id, request_id } => {
                        pool_state.stream_capacity_blocked.store(false, Ordering::Release);
                        let cancelled = cancelled_requests.remove(&request_id);
                        if let Some(meta) = by_request.remove(&request_id) {
                        if cancelled || meta.life.cancelled.load(Ordering::Acquire) {
                            controller.shutdown_stream(stream_id, StreamShutdown::Both { read_error_code: H3_REQUEST_CANCELLED, write_error_code: H3_REQUEST_CANCELLED });
                        } else {
                            stream_by_request.insert(request_id, stream_id);
                            by_stream.insert(stream_id, meta);
                        }
                        } else if cancelled {
                            controller.shutdown_stream(stream_id, StreamShutdown::Both { read_error_code: H3_REQUEST_CANCELLED, write_error_code: H3_REQUEST_CANCELLED });
                        }
                    },
                    ClientH3Event::RequestStreamLimitReached { .. } => {
                        pool_state.stream_capacity_blocked.store(true, Ordering::Release);
                    },
                    ClientH3Event::InformationalHeaders { stream_id, headers } => if let Some(meta) = by_stream.get(&stream_id) {
                        let mut status = 0;
                        for header in &headers {
                            if header.name() == b":status" {
                                status = str::from_utf8(header.value()).ok().and_then(|value| value.parse().ok()).unwrap_or(0);
                            }
                        }
                        let encoded = encode_headers(&headers);
                        let failed = {
                            let _guard = meta.life.callback_gate.lock().unwrap();
                            !meta.life.cancelled.load(Ordering::Acquire)
                                && !meta.life.completed.load(Ordering::Acquire)
                                && (callbacks.on_informational_headers)(
                                    meta.life.state as *mut c_void,
                                    status,
                                    encoded.as_ptr(),
                                    encoded.len(),
                                ) == 0
                        };
                        if failed {
                            meta.life.complete(callbacks.on_complete, Completion::new(1, "Managed informational header processing failed"));
                        }
                    },
                    ClientH3Event::Core(H3Event::IncomingHeaders(incoming)) => if let Some(meta) = by_stream.get(&incoming.stream_id).cloned() {
                        if meta.life.cancelled.load(Ordering::Acquire) {
                            controller.shutdown_stream(incoming.stream_id, StreamShutdown::Both { read_error_code: H3_REQUEST_CANCELLED, write_error_code: H3_REQUEST_CANCELLED });
                            continue;
                        }
                        let mut status = 0;
                        for h in &incoming.headers {
                            if h.name() == b":status" {
                                status = str::from_utf8(h.value()).ok().and_then(|v| v.parse().ok()).unwrap_or(0);
                            }
                        }
                        let encoded = encode_headers(&incoming.headers);
                        let failed = {
                            let _guard = meta.life.callback_gate.lock().unwrap();
                            if meta.life.cancelled.load(Ordering::Acquire)
                                || meta.life.completed.load(Ordering::Acquire)
                            {
                                continue;
                            }
                            (callbacks.on_headers)(
                                meta.life.state as *mut c_void,
                                status,
                                encoded.as_ptr(),
                                encoded.len(),
                            ) == 0
                        };
                        if failed {
                            meta.life.complete(callbacks.on_complete, Completion::new(1, "Managed response header processing failed"));
                            continue;
                        }
                        let mut recv = incoming.recv;
                        let on_body = callbacks.on_body;
                        let on_trailers = callbacks.on_trailers;
                        let complete = callbacks.on_complete;
                        let (finish_tx, finish_rx) = oneshot::channel();
                        finish_by_stream.insert(incoming.stream_id, finish_tx);
                        tokio::spawn(async move {
                            while let Some(frame) = recv.recv().await {
                                let (data, fin) = match frame {
                                    InboundFrame::Body(data, fin) => (data, fin),
                                    InboundFrame::Trailers(headers) => {
                                        let encoded = encode_headers(&headers);
                                        let failed = {
                                            let _guard = meta.life.callback_gate.lock().unwrap();
                                            !meta.life.cancelled.load(Ordering::Acquire)
                                                && !meta.life.completed.load(Ordering::Acquire)
                                                && on_trailers(
                                                    meta.life.state as *mut c_void,
                                                    encoded.as_ptr(),
                                                    encoded.len(),
                                                ) == 0
                                        };
                                        if failed {
                                            meta.life.complete(complete, Completion::new(1, "Managed trailer processing failed"));
                                            return;
                                        }
                                        continue;
                                    },
                                    InboundFrame::Datagram(_) => continue,
                                };
                                let body_result = {
                                    let _guard = meta.life.callback_gate.lock().unwrap();
                                    if meta.life.cancelled.load(Ordering::Acquire)
                                        || meta.life.completed.load(Ordering::Acquire)
                                    {
                                        break;
                                    }
                                    if data.is_empty() {
                                        1
                                    } else {
                                        on_body(
                                            meta.life.state as *mut c_void,
                                            data.as_ptr(),
                                            data.len(),
                                        )
                                    }
                                };
                                if body_result == 2 {
                                    meta.life.complete(complete, Completion::new(1, "Managed response body processing failed"));
                                    return;
                                }
                                if body_result == 0 {
                                    meta.life.body_resume.notified().await;
                                    if meta.life.cancelled.load(Ordering::Acquire)
                                        || meta.life.completed.load(Ordering::Acquire)
                                    {
                                        break;
                                    }
                                }
                                if fin {
                                    break;
                                }
                            }
                            if finish_rx.await.is_ok() && !meta.life.cancelled.load(Ordering::Acquire) {
                                meta.life.complete(complete, Completion::new(0, ""));
                            }
                        });
                    },
                    ClientH3Event::Core(H3Event::BodyBytesReceived { stream_id, fin: true, .. }) => {
                        pool_state.stream_capacity_blocked.store(false, Ordering::Release);
                        if let Some(finish) = finish_by_stream.remove(&stream_id) { let _ = finish.send(()); }
                        by_stream.remove(&stream_id);
                        stream_by_request.retain(|_, value| *value != stream_id);
                    },
                    ClientH3Event::Core(H3Event::ResetStream { stream_id, error_code }) => if let Some(meta) = by_stream.remove(&stream_id) { pool_state.stream_capacity_blocked.store(false, Ordering::Release); let response_started = finish_by_stream.remove(&stream_id).is_some(); stream_by_request.retain(|_, value| *value != stream_id); if !meta.life.cancelled.load(Ordering::Acquire) { meta.life.complete(callbacks.on_complete, Completion::stream_reset(error_code, response_started, &format!("HTTP/3 stream reset ({error_code:#x})"))); } },
                    ClientH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                        pool_state.stream_capacity_blocked.store(false, Ordering::Release);
                        let response_started = if let Some(finish) = finish_by_stream.remove(&stream_id) { let _ = finish.send(()); true } else { false };
                        if let Some(meta) = by_stream.remove(&stream_id) {
                            if !response_started && !meta.life.cancelled.load(Ordering::Acquire) {
                                meta.life.complete(callbacks.on_complete, Completion::new(5, "HTTP/3 stream closed before response headers"));
                            }
                        }
                        stream_by_request.retain(|_, value| *value != stream_id);
                    },
                    ClientH3Event::Core(H3Event::GoAway { id }) => {
                        draining.store(true, Ordering::Release);
                        let rejected = by_stream
                            .keys()
                            .copied()
                            .filter(|stream_id| *stream_id >= id)
                            .collect::<Vec<_>>();
                        for stream_id in rejected {
                            controller.shutdown_stream(stream_id, StreamShutdown::Both {
                                read_error_code: H3_REQUEST_CANCELLED,
                                write_error_code: H3_REQUEST_CANCELLED,
                            });
                            if let Some(meta) = by_stream.remove(&stream_id) {
                                finish_by_stream.remove(&stream_id);
                                stream_by_request.retain(|_, value| *value != stream_id);
                                meta.life.complete(callbacks.on_complete, Completion::new(4, "HTTP/3 request was not processed before GOAWAY"));
                            }
                        }
                    },
                    ClientH3Event::Core(H3Event::ConnectionError(e)) => {
                        draining.store(true, Ordering::Release);
                        pool_state.accepting.store(false, Ordering::Release);
                        let message = e.to_string();
                        let (error_kind, protocol_code) = h3_protocol_error_details(&e);
                        complete_actor_requests(&mut by_request, &mut by_stream, &mut pending, &mut stream_by_request, &mut finish_by_stream, &mut cancelled_requests, callbacks.on_complete, 5, error_kind, protocol_code, &message);
                        return Err(std::io::Error::other(message));
                    },
                    ClientH3Event::Core(H3Event::ConnectionShutdown(e)) => {
                        draining.store(true, Ordering::Release);
                        pool_state.accepting.store(false, Ordering::Release);
                        let message = format!("connection shut down: {e:?}");
                        let (error_kind, protocol_code) = match e.as_ref() {
                            Some(H3ConnectionError::H3(error)) => h3_protocol_error_details(error),
                            Some(_) => (3, u64::MAX),
                            None => (1, u64::MAX),
                        };
                        complete_actor_requests(&mut by_request, &mut by_stream, &mut pending, &mut stream_by_request, &mut finish_by_stream, &mut cancelled_requests, callbacks.on_complete, 5, error_kind, protocol_code, &message);
                        return Err(std::io::Error::other(message));
                    },
                    _ => {}
                },
                else => break,
            }
            if in_early_data && handshake_established.load(Ordering::Acquire) {
                in_early_data = false;
                next_handshake_check = None;
            }
            if session_stored.load(Ordering::Acquire) {
                next_session_check = None;
            }
            while !draining.load(Ordering::Acquire)
                && !pool_state.stream_capacity_blocked.load(Ordering::Acquire)
            {
                let index = if in_early_data {
                    pending.iter().position(|command| command.allow_early_data)
                } else if pending.is_empty() {
                    None
                } else {
                    Some(0)
                };
                let Some(index) = index else { break };
                let command = pending.remove(index).unwrap();
                if command.life.cancelled.load(Ordering::Acquire) { continue; }
                if in_early_data {
                    early_data_was_sent.store(true, Ordering::Release);
                    early_data_stats.attempts.fetch_add(1, Ordering::Relaxed);
                }
                submit_to_driver(command, &request_sender, &mut by_request)?;
            }
            if (draining.load(Ordering::Acquire) || !pool_state.accepting.load(Ordering::Acquire))
                && by_request.is_empty()
                && by_stream.is_empty()
                && cancelled_requests.is_empty()
                && pending.is_empty()
            {
                break;
            }
        }
        complete_actor_requests(&mut by_request, &mut by_stream, &mut pending, &mut stream_by_request, &mut finish_by_stream, &mut cancelled_requests, callbacks.on_complete, 5, 3, u64::MAX, "HTTP/3 connection stopped before all requests completed");
        Ok::<(), std::io::Error>(())
    }.await;
    draining.store(true, Ordering::Release);
    let (code, error_kind, message) = match result {
        Ok(()) => (4, 3, "HTTP/3 connection is draining".to_owned()),
        Err(error) => {
            let message = error.to_string();
            let lower = message.to_ascii_lowercase();
            let kind = if lower.contains("handshake")
                || lower.contains("certificate")
                || lower.contains("tls")
            {
                4
            } else {
                3
            };
            (1, kind, message)
        }
    };
    while let Ok(command) = commands.try_recv() {
        if let ActorCommand::Submit(command) = command {
            command.life.complete(
                callbacks.on_complete,
                Completion {
                    code,
                    error_kind,
                    protocol_code: u64::MAX,
                    message: &message,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
