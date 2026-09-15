use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

use autojoin_bot::ScannerClient;
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{SecretKey, aead::OsRng};
use serde_json::{Value, json};
use snarkvm_console::{
    account::{Field, PrivateKey, ViewKey},
    prelude::{Network, One, TestnetV0, ToField},
};

const UUID: &str = "123field";

struct Response {
    path: &'static str,
    status: u16,
    body: Value,
    delay: Duration,
}

fn response(path: &'static str, status: u16, body: Value) -> Response {
    Response {
        path,
        status,
        body,
        delay: Duration::ZERO,
    }
}

// Exercise the real HTTP client, including JSON request bodies and cancellation.
fn server(responses: Vec<Response>) -> (ScannerClient, thread::JoinHandle<Vec<Value>>) {
    server_with_timing(responses, Duration::from_millis(1), Duration::from_secs(5))
}

fn server_with_timing(
    responses: Vec<Response>,
    poll_interval: Duration,
    sync_timeout: Duration,
) -> (ScannerClient, thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = ScannerClient::new(
        format!("http://{}", listener.local_addr().unwrap()),
        poll_interval,
        sync_timeout,
    );
    let handle = thread::spawn(move || {
        let mut bodies = Vec::new();
        for response in responses {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "missing request: {}",
                            response.path
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert_eq!(request_line.split_whitespace().nth(1), Some(response.path));
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                assert!(
                    reader.read_line(&mut line).unwrap() > 0,
                    "incomplete request headers"
                );
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            bodies.push(if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            });
            thread::sleep(response.delay);
            let body = response.body.to_string();
            // A timed-out client may have closed the socket already.
            let _ = write!(
                stream,
                "HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.status,
                body.len(),
                body
            );
        }
        bodies
    });
    (client, handle)
}

fn view_key() -> ViewKey<TestnetV0> {
    let private_key = PrivateKey::new(&mut rand::rng()).unwrap();
    ViewKey::try_from(&private_key).unwrap()
}

fn scanner_uuid(view_key: &ViewKey<TestnetV0>) -> String {
    let domain = Field::<TestnetV0>::new_domain_separator("RecordScannerV0");
    TestnetV0::hash_psd4(&[
        domain,
        view_key.to_field().unwrap(),
        Field::<TestnetV0>::one(),
    ])
    .unwrap()
    .to_string()
}

#[tokio::test]
async fn syncing_registration_is_polled_without_reregistering() {
    let key = view_key();
    let uuid = scanner_uuid(&key);
    let (client, server) = server(vec![
        response("/status", 200, json!({ "synced": false })),
        response("/status", 200, json!({ "synced": true })),
    ]);

    assert_eq!(client.ensure_ready(&key, 42).await.unwrap(), uuid);
    let requests = server.join().unwrap();
    assert_eq!(requests, vec![json!(uuid), json!(uuid)]);
}

#[tokio::test]
async fn waits_for_synced_before_reading_the_initial_snapshot() {
    let (client, server) = server(vec![
        response("/status", 200, json!({ "synced": false, "percentage": 0 })),
        response(
            "/status",
            200,
            json!({ "synced": false, "percentage": 100 }),
        ),
        response("/status", 200, json!({ "synced": true, "percentage": 100 })),
        response(
            "/records/owned",
            200,
            json!([{ "tag": "1field" }, { "tag": "2field" }]),
        ),
        response(
            "/records/tags",
            200,
            json!({ "1field": false, "2field": false }),
        ),
    ]);
    let key = view_key();
    client.wait_for_sync(&key, UUID, 42).await.unwrap();
    let records = client
        .fetch_unspent(&key, UUID, 42, None, None)
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    let requests = server.join().unwrap();
    assert_eq!(&requests[..3], &[json!(UUID), json!(UUID), json!(UUID)]);
    assert_eq!(requests[3]["uuid"], UUID);
    assert_eq!(requests[3]["unspent"], true);
}

#[tokio::test]
async fn synchronized_empty_and_single_record_accounts_finish_normally() {
    for count in [0, 1] {
        let records = vec![json!({ "tag": "1field" }); count];
        let mut responses = vec![
            response("/status", 200, json!({ "synced": true })),
            response("/records/owned", 200, json!(records)),
        ];
        if count > 0 {
            responses.push(response("/records/tags", 200, json!({ "1field": false })));
        }
        let (client, server) = server(responses);
        let key = view_key();
        client.wait_for_sync(&key, UUID, 0).await.unwrap();
        assert_eq!(
            client
                .fetch_unspent(&key, UUID, 0, None, None)
                .await
                .unwrap()
                .len(),
            count
        );
        server.join().unwrap();
    }
}

#[tokio::test]
async fn startup_timeout_cancels_both_polling_and_a_stalled_http_response() {
    for response_delay in [Duration::ZERO, Duration::from_millis(200)] {
        let mut pending = response("/status", 200, json!({ "synced": false }));
        pending.delay = response_delay;
        let (client, server) = server_with_timing(
            vec![pending],
            Duration::from_secs(10),
            Duration::from_millis(100),
        );
        let error = client
            .wait_for_sync(&view_key(), UUID, 0)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("timed out waiting for initial scanner synchronization")
        );
        server.join().unwrap();
    }
}

#[tokio::test]
async fn status_errors_and_missing_flags_fail_without_reading_records() {
    for (status, body, expected) in [
        (503, json!({ "message": "unavailable" }), "HTTP 503"),
        (200, json!({ "percentage": 100 }), "invalid JSON"),
    ] {
        let (client, server) = server(vec![response("/status", status, body)]);
        let error = client
            .wait_for_sync(&view_key(), UUID, 0)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "unexpected error: {error}"
        );
        server.join().unwrap();
    }
}

#[tokio::test]
async fn status_422_re_registers_once_with_the_original_start_block() {
    let secret_key = SecretKey::generate(&mut OsRng);
    let public_key = secret_key.public_key();
    for repeated_422 in [false, true] {
        let key = view_key();
        let uuid = scanner_uuid(&key);
        let (client, server) = server(vec![
            response("/status", 422, json!({ "message": "not registered" })),
            response(
                "/pubkey",
                200,
                json!({ "key_id": "test-key", "public_key": STANDARD.encode(public_key.as_bytes()) }),
            ),
            response("/register/encrypted", 200, json!({ "uuid": uuid.clone() })),
            response(
                "/status",
                if repeated_422 { 422 } else { 200 },
                if repeated_422 {
                    json!({ "message": "not registered" })
                } else {
                    json!({ "synced": true })
                },
            ),
        ]);
        let result = client.wait_for_sync(&key, &uuid, 42).await;
        if repeated_422 {
            assert!(result.unwrap_err().to_string().contains("HTTP 422"));
        } else {
            result.unwrap();
        }
        let requests = server.join().unwrap();
        let encrypted = STANDARD
            .decode(requests[2]["ciphertext"].as_str().unwrap())
            .unwrap();
        let plaintext = secret_key.unseal(&encrypted).unwrap();
        assert_eq!(&plaintext[plaintext.len() - 4..], &42u32.to_le_bytes());
    }
}

#[tokio::test]
async fn owned_422_discards_partial_pages_and_restarts_after_sync() {
    let key = view_key();
    let uuid = scanner_uuid(&key);
    let secret_key = SecretKey::generate(&mut OsRng);
    let public_key = secret_key.public_key();
    let first_page: Vec<_> = (0..1000)
        .map(|index| json!({ "commitment": format!("old-{index}") }))
        .collect();
    let (client, server) = server(vec![
        response("/records/owned", 200, json!(first_page)),
        response(
            "/records/owned",
            422,
            json!({ "message": "not registered" }),
        ),
        response(
            "/pubkey",
            200,
            json!({
                "key_id": "test-key",
                "public_key": STANDARD.encode(public_key.as_bytes()),
            }),
        ),
        response("/register/encrypted", 200, json!({ "uuid": uuid.clone() })),
        response("/status", 200, json!({ "synced": false })),
        response("/status", 200, json!({ "synced": true })),
        response(
            "/records/owned",
            200,
            json!([{ "commitment": "replacement" }]),
        ),
    ]);

    let records = client
        .fetch_unspent(&key, &uuid, 42, None, None)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].commitment.as_deref(), Some("replacement"));

    let requests = server.join().unwrap();
    assert_eq!(requests[0]["filter"]["page"], 0);
    assert_eq!(requests[1]["filter"]["page"], 1);
    assert_eq!(requests[6]["filter"]["page"], 0);
    assert_eq!(requests[4], json!(uuid));
    assert_eq!(requests[5], json!(uuid));
}
