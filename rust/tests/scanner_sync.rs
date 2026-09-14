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
    account::{PrivateKey, ViewKey},
    prelude::TestnetV0,
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = ScannerClient::new(format!("http://{}", listener.local_addr().unwrap()));
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
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse::<usize>().unwrap();
                    }
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
    client
        .wait_for_sync(
            &key,
            UUID,
            42,
            Duration::from_millis(1),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
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
        client
            .wait_for_sync(
                &key,
                UUID,
                0,
                Duration::from_secs(1),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
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
        let (client, server) = server(vec![pending]);
        let error = client
            .wait_for_sync(
                &view_key(),
                UUID,
                0,
                Duration::from_secs(10),
                Duration::from_millis(100),
            )
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
            .wait_for_sync(
                &view_key(),
                UUID,
                0,
                Duration::from_millis(1),
                Duration::from_secs(5),
            )
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
        let (client, server) = server(vec![
            response("/status", 422, json!({ "message": "not registered" })),
            response(
                "/pubkey",
                200,
                json!({ "key_id": "test-key", "public_key": STANDARD.encode(public_key.as_bytes()) }),
            ),
            response("/register/encrypted", 200, json!({ "uuid": UUID })),
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
        let result = client
            .wait_for_sync(
                &view_key(),
                UUID,
                42,
                Duration::from_millis(1),
                Duration::from_secs(5),
            )
            .await;
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
