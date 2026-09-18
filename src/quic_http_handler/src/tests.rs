use crate::client::*;
use crate::qlog::{QlogCallbackWriter, QlogSettings};
use crate::tls::{origin_key, TlsSettings};
use std::io::Write;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

static COMPLETIONS: AtomicUsize = AtomicUsize::new(0);
static QLOG_RECORDS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

extern "C" fn count_completion(_: *mut c_void, _: i32, _: i32, _: u64, _: *const u8, _: usize) {
    COMPLETIONS.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn collect_qlog(
    _: *mut c_void,
    connection_id: *const u8,
    connection_id_length: usize,
    json: *const u8,
    json_length: usize,
) -> u8 {
    let connection_id = unsafe { std::slice::from_raw_parts(connection_id, connection_id_length) };
    let json = unsafe { std::slice::from_raw_parts(json, json_length) };
    QLOG_RECORDS.lock().unwrap().push((
        String::from_utf8(connection_id.to_vec()).unwrap(),
        String::from_utf8(json.to_vec()).unwrap(),
    ));
    1
}

#[test]
fn ffi_bytes_rejects_null_pointer_with_nonzero_length() {
    assert!(unsafe { RawSlice::from_raw(std::ptr::null(), 1) }.is_err());
    assert!(unsafe { RawSlice::from_raw(std::ptr::null(), 0) }
        .unwrap()
        .as_slice()
        .is_empty());
}

#[test]
fn reset_before_response_is_reported_as_unprocessed() {
    assert_eq!(Completion::stream_reset(0x010b, false, "").code, 6);
    assert_eq!(
        Completion::stream_reset(H3_REQUEST_CANCELLED, false, "").code,
        5
    );
    assert_eq!(
        Completion::stream_reset(H3_REQUEST_CANCELLED, true, "").code,
        2
    );
}

#[test]
fn request_completion_is_exactly_once_under_racing_paths() {
    COMPLETIONS.store(0, Ordering::Relaxed);
    let life = Arc::new(RequestLife {
        state: 0,
        cancelled: AtomicBool::new(false),
        completed: AtomicBool::new(false),
        callback_gate: Mutex::new(()),
        body_resume: Notify::new(),
        pool_state: OnceLock::new(),
    });
    let threads = (0..16)
        .map(|_| {
            let life = life.clone();
            std::thread::spawn(move || {
                life.complete(count_completion, Completion::new(1, "failed"))
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(COMPLETIONS.load(Ordering::Relaxed), 1);
}

#[test]
fn happy_eyeballs_interleaves_address_families_without_losing_addresses() {
    let v6a = "2001:db8::1".parse().unwrap();
    let v6b = "2001:db8::2".parse().unwrap();
    let v4a = "192.0.2.1".parse().unwrap();
    let v4b = "192.0.2.2".parse().unwrap();
    assert_eq!(
        happy_eyeballs_order(&[v6a, v6b, v4a, v4b]),
        vec![v6a, v4a, v6b, v4b]
    );
    assert_eq!(happy_eyeballs_order(&[v4a, v4b, v6a]), vec![v4a, v6a, v4b]);
}

#[test]
fn origin_key_separates_tls_and_sni_configuration() {
    let defaults = TlsSettings::default();
    let mut other_sni = defaults.clone();
    other_sni.override_server_name = Some("other.example".to_owned());
    let mut other_roots = defaults.clone();
    other_roots.root_certificates = b"different trust".to_vec();
    let mut replaced_roots = defaults.clone();
    replaced_roots.replace_default_roots = true;

    assert_ne!(
        origin_key("example.com", 443, &defaults),
        origin_key("example.com", 443, &other_sni)
    );
    assert_ne!(
        origin_key("example.com", 443, &defaults),
        origin_key("example.com", 443, &other_roots)
    );
    assert_ne!(
        origin_key("example.com", 443, &defaults),
        origin_key("example.com", 443, &replaced_roots)
    );
    assert_ne!(
        origin_key("example.com", 443, &defaults),
        origin_key("example.com", 8443, &defaults)
    );
}

#[test]
fn qlog_writer_forwards_fragmented_json_sequence_records() {
    QLOG_RECORDS.lock().unwrap().clear();
    let mut writer = QlogCallbackWriter {
        settings: QlogSettings {
            state: 0,
            callback: Some(collect_qlog),
        },
        connection_id: Arc::from(&b"connection-id"[..]),
        pending: Vec::new(),
        enabled: true,
    };

    writer.write_all(b"\x1e{\"first\":").unwrap();
    writer.write_all(b"1}\n\x1e{\"second\":2}\n").unwrap();

    assert_eq!(
        *QLOG_RECORDS.lock().unwrap(),
        vec![
            ("connection-id".to_owned(), "{\"first\":1}".to_owned()),
            ("connection-id".to_owned(), "{\"second\":2}".to_owned()),
        ]
    );
}
