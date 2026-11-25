// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Concurrency and validation tests for per-MD5 session lifecycle locks and GUI session attach.

use super::*;
use crate::bridge::{agent_ws, AGENT_WS_PATH};
use crate::config::McpConfig;
use crate::error::RPC_CODE_INVALID_ARGUMENT;
use crate::state::{test_state, test_state_with_config, test_state_with_ws_url, ConnectionHandle};
use axum::extract::ws::Message;
use axum::{routing::get, Router};
use serde_json::Map;
use std::net::SocketAddr;
use std::sync::Barrier;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Valid canonical MD5 for Binary A.
const MD5_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Valid canonical MD5 for Binary B.
const MD5_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Makes isolated daemon state with a custom disconnect grace period.
fn state_with_grace(root: &Path, grace: Duration) -> Arc<McpState> {
    let mut config = McpConfig::default();
    config.timeouts.bridge_disconnect_grace = grace;
    config.timeouts.graceful_kill = Duration::from_millis(300);
    config.timeouts.force_kill = Duration::from_millis(300);
    test_state_with_config(root, config)
}

/// Starts a child process that stays alive until the daemon terminates it.
fn spawn_long_child() -> ManagedChild {
    #[cfg(unix)]
    let mut command = {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        cmd
    };
    #[cfg(windows)]
    let mut command = {
        let mut cmd = Command::new("ping");
        cmd.args(["-n", "31", "127.0.0.1"]);
        cmd
    };
    command.stdout(Stdio::null()).stderr(Stdio::null());
    ManagedChild::spawn(&mut command).expect("spawn test child")
}

/// Starts an Axum WebSocket listener for `/ws/agent` on an ephemeral loopback port.
async fn start_ws_server(state: Arc<McpState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (address, task)
}

/// Sends an HTTP WebSocket upgrade request and returns the raw status line and stream.
async fn upgrade_bridge(address: SocketAddr, token: &str) -> (String, TcpStream) {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "GET {AGENT_WS_PATH} HTTP/1.1\r\nHost: {address}\r\n\
         Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await.unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
            break;
        }
    }
    (status_line, reader.into_inner())
}

/// Opens an authenticated WebSocket client to `/ws/agent`.
async fn connect_bridge(address: SocketAddr, token: &str) -> TcpStream {
    let (status, stream) = upgrade_bridge(address, token).await;
    assert!(status.starts_with("HTTP/1.1 101 "), "{status}");
    stream
}

/// Sends one masked WebSocket text frame to the server.
async fn send_ws_text(socket: &mut TcpStream, text: &str) {
    let length = u16::try_from(text.len()).unwrap();
    let mask: [u8; 4] = Uuid::new_v4().as_bytes()[..4].try_into().unwrap();
    let mut frame = vec![0x81];
    if length < 126 {
        frame.push(0x80 | u8::try_from(length).unwrap());
    } else {
        frame.push(0xfe);
        frame.extend_from_slice(&length.to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        text.bytes()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    socket.write_all(&frame).await.unwrap();
}

/// Reads one unmasked WebSocket text frame from the server.
async fn recv_ws_text(socket: &mut TcpStream) -> Value {
    loop {
        let mut header = [0_u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        let opcode = header[0] & 0x0f;
        assert_eq!(header[1] & 0x80, 0, "server frames must not be masked");
        let length = match header[1] & 0x7f {
            126 => {
                let mut ext = [0_u8; 2];
                socket.read_exact(&mut ext).await.unwrap();
                usize::from(u16::from_be_bytes(ext))
            }
            127 => {
                let mut ext = [0_u8; 8];
                socket.read_exact(&mut ext).await.unwrap();
                usize::try_from(u64::from_be_bytes(ext)).unwrap()
            }
            short => usize::from(short),
        };
        let mut payload = vec![0_u8; length];
        socket.read_exact(&mut payload).await.unwrap();
        if opcode == 0x1 {
            return serde_json::from_slice(&payload).unwrap();
        }
    }
}

/// Installs a ready connected session with an in-memory channel handle.
fn put_ready_session(state: &McpState, md5: &str) -> mpsc::UnboundedReceiver<Message> {
    let token = Uuid::new_v4().simple().to_string();
    let mut record = SessionRecord::launching(md5.to_string(), "sample.bin".into(), token);
    record.mark_ready();
    state.put_session(&record).unwrap();
    let (sender, receiver) = mpsc::unbounded_channel();
    assert!(state.attach_bridge(
        md5,
        ConnectionHandle {
            conn_id: Uuid::new_v4().to_string(),
            sender,
        },
    ));
    receiver
}

/// Asserts that `error` is an `InvalidArgument` domain error for `md5`.
fn assert_invalid_md5(error: &anyhow::Error) {
    match error.downcast_ref::<DomainError>() {
        Some(domain @ DomainError::InvalidArgument { param, .. }) => {
            assert_eq!(param, "md5");
            assert_eq!(domain.rpc_code(), RPC_CODE_INVALID_ARGUMENT);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Checks that invalid MD5 values fail validation before lifecycle lock allocation.
#[tokio::test]
async fn rejects_invalid_md5_before_lifecycle_lock_allocation() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path());
    for invalid in [
        "",
        "0123456789abcdef",
        "0123456789abcdef0123456789abcdeg",
        "../0123456789abcdef0123456789ab",
    ] {
        let err = state.lifecycle_lock(invalid).unwrap_err();
        assert_invalid_md5(&err);
        let open_err = open(&state, invalid.to_string(), None, None)
            .await
            .unwrap_err();
        assert_invalid_md5(&open_err);
        let attach_err = attach(&state, invalid.to_string(), None, None)
            .await
            .unwrap_err();
        assert_invalid_md5(&attach_err);
        let close_err = close(&state, invalid, false).await.unwrap_err();
        assert_invalid_md5(&close_err);
        let conn_err = ensure_connected(&state, invalid).await.unwrap_err();
        assert_invalid_md5(&conn_err);
        assert_eq!(state.lifecycle_lock_count(), 0);
    }

    let upper = state
        .lifecycle_lock("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .unwrap();
    let lower = state.lifecycle_lock(MD5_A).unwrap();
    assert!(Arc::ptr_eq(&upper, &lower));
    assert_eq!(state.lifecycle_lock_count(), 1);

    let second = state.lifecycle_lock(MD5_B).unwrap();
    assert!(!Arc::ptr_eq(&lower, &second));
    assert_eq!(state.lifecycle_lock_count(), 2);
}

/// Checks that `session::open` reuse on Binary B finishes under 50 ms while Binary A closes.
#[tokio::test]
async fn reuses_ready_session_under_50ms_during_unrelated_close() {
    let root = tempfile::tempdir().unwrap();
    let state = state_with_grace(root.path(), Duration::from_secs(2));
    let mut rx_a = put_ready_session(&state, MD5_A);
    let _rx_b = put_ready_session(&state, MD5_B);
    state.register_process(MD5_A, spawn_long_child()).unwrap();

    let close_state = state.clone();
    let close_task = tokio::spawn(async move { close(&close_state, MD5_A, false).await });

    // Wait until Binary A sends `session.shutdown` while its lifecycle lock stays held.
    let frame = tokio::time::timeout(Duration::from_secs(1), rx_a.recv())
        .await
        .expect("shutdown request sent")
        .expect("frame");
    let Message::Text(wire) = frame else {
        panic!("expected text frame");
    };
    let parsed: Value = serde_json::from_str(&wire).unwrap();
    assert_eq!(parsed["method"], "session.shutdown");
    assert!(state.lifecycle_lock(MD5_A).unwrap().try_lock().is_err());

    let started = std::time::Instant::now();
    let (summary, payload) = open(
        &state,
        MD5_B.to_uppercase(),
        None,
        Some(Duration::from_secs(1)),
    )
    .await
    .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(50),
        "open reuse took {elapsed:?}"
    );
    assert_eq!(summary, format!("Reused session {MD5_B}"));
    assert_eq!(payload["created"], false);
    assert_eq!(payload["reused"], true);
    assert_eq!(payload["session"]["status"], "ready");
    assert!(!close_task.is_finished());

    state.stop_process(MD5_A, Duration::ZERO).await;
    drop(rx_a);
    close_task.await.unwrap().unwrap();
    assert_eq!(state.session(MD5_A).unwrap().status, SessionStatus::Closed);
}

/// Checks that `bridge::handshake` for Binary B finishes while Binary A waits in `reap_or_kill`.
#[tokio::test]
async fn completes_handshake_while_other_session_waits_in_reap_or_kill() {
    let root = tempfile::tempdir().unwrap();
    let state = state_with_grace(root.path(), Duration::from_secs(2));
    let (address, server) = start_ws_server(state.clone()).await;

    let rx_a = put_ready_session(&state, MD5_A);
    // Drop the receiver so `session.shutdown` fails at once and `close` enters `reap_or_kill`.
    drop(rx_a);
    state.register_process(MD5_A, spawn_long_child()).unwrap();

    let close_state = state.clone();
    let close_task = tokio::spawn(async move { close(&close_state, MD5_A, false).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while state.lifecycle_lock(MD5_A).unwrap().try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Binary A holds its lifecycle lock in reap_or_kill");

    let token_b = Uuid::new_v4().simple().to_string();
    let mut record_b = SessionRecord::launching(MD5_B.into(), "b.bin".into(), token_b.clone());
    record_b.mark_starting();
    state.put_session(&record_b).unwrap();
    let job_b = state.insert_job(job_kind::ANALYZE_BINARY, Some(MD5_B.into()));
    state.set_launch_job(MD5_B, Some(job_b.id.clone()));

    let mut socket_b = connect_bridge(address, &token_b).await;
    send_ws_text(
        &mut socket_b,
        &json!({
            "jsonrpc": "2.0",
            "method": "ghidra.ready",
            "params": { "session_id": MD5_B, "program_name": "b.bin" }
        })
        .to_string(),
    )
    .await;

    let completed = wait_ready(&state, MD5_B, &job_b.id, Duration::from_millis(500))
        .await
        .expect("Binary B handshake and wait_ready finish while Binary A reaps");
    assert_eq!(completed.status, JobStatus::Completed);
    assert_eq!(state.session(MD5_B).unwrap().status, SessionStatus::Ready);
    assert!(
        !close_task.is_finished(),
        "Binary A must still wait in reap_or_kill"
    );

    close_task.await.unwrap().unwrap();
    drop(socket_b);
    server.abort();
}

/// Checks that four concurrent `on_disconnect` events stop their processes in parallel.
#[tokio::test]
async fn disconnects_four_sessions_in_parallel_without_serial_grace_delay() {
    let grace = Duration::from_millis(450);
    let root = tempfile::tempdir().unwrap();
    let state = state_with_grace(root.path(), grace);
    let (address, server) = start_ws_server(state.clone()).await;

    let md5s = [
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "33333333333333333333333333333333",
        "44444444444444444444444444444444",
    ];
    let mut sockets = Vec::new();
    for md5 in md5s {
        let token = Uuid::new_v4().simple().to_string();
        state
            .put_session(&SessionRecord::launching(
                md5.into(),
                "bin".into(),
                token.clone(),
            ))
            .unwrap();
        state.register_process(md5, spawn_long_child()).unwrap();
        let mut socket = connect_bridge(address, &token).await;
        send_ws_text(
            &mut socket,
            &json!({
                "jsonrpc": "2.0",
                "method": "ghidra.ready",
                "params": { "session_id": md5, "program_name": "bin" }
            })
            .to_string(),
        )
        .await;
        sockets.push(socket);
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        while !md5s
            .iter()
            .all(|md5| state.session(md5).unwrap().status == SessionStatus::Ready)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all four sessions reach Ready");

    let started = std::time::Instant::now();
    drop(sockets);
    tokio::time::timeout(Duration::from_secs(3), async {
        while !md5s
            .iter()
            .all(|md5| state.session(md5).unwrap().status == SessionStatus::Disconnected)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all four sessions finish on_disconnect");
    let elapsed = started.elapsed();

    // Serial execution takes at least 4 * 450 ms = 1800 ms.
    assert!(
        elapsed < Duration::from_millis(1350),
        "four concurrent disconnects took {elapsed:?}; expected parallel execution"
    );
    server.abort();
}

/// Checks that slow-path `session::open` checks ready state, launch jobs, and shutdown again.
#[tokio::test]
async fn slow_path_open_rechecks_ready_launch_job_and_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path());

    // Case 1: Session transitions from Launching to Ready while `open` waits for its MD5 lock.
    let token = Uuid::new_v4().simple().to_string();
    state
        .put_session(&SessionRecord::launching(
            MD5_A.into(),
            "a.bin".into(),
            token,
        ))
        .unwrap();
    let guard = state.lifecycle_lock(MD5_A).unwrap().lock_owned().await;
    let open_state = state.clone();
    let waiter = tokio::spawn(async move { open(&open_state, MD5_A.into(), None, None).await });
    tokio::task::yield_now().await;
    let _rx = put_ready_session(&state, MD5_A);
    drop(guard);
    let (_, reused) = waiter.await.unwrap().unwrap();
    assert_eq!(reused["reused"], true);
    assert_eq!(reused["created"], false);

    // Case 2: Active launch job appears while `open` waits for its MD5 lock.
    let guard_b = state.lifecycle_lock(MD5_B).unwrap().lock_owned().await;
    let open_state = state.clone();
    let waiter_b = tokio::spawn(async move { open(&open_state, MD5_B.into(), None, None).await });
    tokio::task::yield_now().await;
    state
        .put_session(&SessionRecord::launching(
            MD5_B.into(),
            "b.bin".into(),
            "tok".into(),
        ))
        .unwrap();
    let job = state.insert_job(job_kind::ANALYZE_BINARY, Some(MD5_B.into()));
    state.set_launch_job(MD5_B, Some(job.id.clone()));
    drop(guard_b);
    let (_, joined) = waiter_b.await.unwrap().unwrap();
    assert_eq!(joined["jobId"], job.id);
    assert_eq!(joined["reused"], true);

    // Case 3: Shutdown starts while `open` waits on the slow path.
    let md5_c = "cccccccccccccccccccccccccccccccc";
    let guard_c = state.lifecycle_lock(md5_c).unwrap().lock_owned().await;
    let open_state = state.clone();
    let waiter_c = tokio::spawn(async move { open(&open_state, md5_c.into(), None, None).await });
    tokio::task::yield_now().await;
    state.begin_shutdown();
    drop(guard_c);
    let err = waiter_c.await.unwrap().unwrap_err();
    assert_eq!(
        err.downcast_ref::<DomainError>(),
        Some(&DomainError::ShuttingDown)
    );
}

/// Checks that concurrent launches install the shared bridge runtime files without errors.
#[test]
fn synchronizes_concurrent_bridge_runtime_installs() {
    let root = tempfile::tempdir().unwrap();
    let runtime_dir = root.path().join("runtime");
    let workers = 8;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let dir = runtime_dir.clone();
        let sync = barrier.clone();
        handles.push(std::thread::spawn(move || {
            sync.wait();
            bridge::install_runtime(&dir).unwrap()
        }));
    }
    for handle in handles {
        let jar = handle.join().unwrap();
        assert!(jar.is_file());
    }
    assert!(runtime_dir.join(bridge::BRIDGE_SCRIPT_NAME).is_file());
    assert!(runtime_dir
        .join(bridge::SAVED_PROJECT_SCRIPT_NAME)
        .is_file());
}

/// Makes sure that an attached GUI session completes `ghidra.ready`, serves RPC calls,
/// and never starts headless recovery after disconnect.
#[tokio::test]
async fn attach_accepts_outbound_handshake_and_skips_headless_recovery() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ws_url = format!("ws://{address}{AGENT_WS_PATH}");
    let state = test_state_with_ws_url(root.path(), ws_url.clone());
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let md5 = "0123456789abcdef0123456789abcdef";

    let (_, attached) = attach(&state, md5.into(), None, None).await.unwrap();
    let token = attached["token"].as_str().unwrap().to_string();
    let job_id = attached["jobId"].as_str().unwrap().to_string();
    assert_eq!(attached["wsUrl"], ws_url);
    assert_eq!(attached["sessionId"], md5);
    assert_eq!(
        attached["bridgeArgs"],
        format!("ws_url={ws_url} session_id={md5} token={token}")
    );
    assert!(!attached["bridgeArgs"]
        .as_str()
        .unwrap()
        .contains("exit_deadline_sec"));
    assert!(attached["session"].get("token").is_none());

    let mut socket = connect_bridge(address, &token).await;
    send_ws_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "method": "ghidra.ready",
            "params": { "session_id": md5, "program_name": "gui_target.exe" }
        })
        .to_string(),
    )
    .await;

    let job = state
        .await_job(&job_id, Some(Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(job.status, JobStatus::Completed);
    let session = state.session(md5).unwrap();
    assert_eq!(session.status, SessionStatus::Ready);
    assert!(session.ws_connected);
    assert!(session.attached);
    assert_eq!(session.file_name, "gui_target.exe");

    let rpc_state = state.clone();
    let call_task =
        tokio::spawn(async move { call(&rpc_state, md5, "program.get", json!({})).await });
    let rpc_request = recv_ws_text(&mut socket).await;
    assert_eq!(rpc_request["method"], "program.get");
    let req_id = rpc_request["id"].as_str().unwrap();
    send_ws_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": { "program_name": "gui_target.exe" }
        })
        .to_string(),
    )
    .await;
    let envelope = call_task.await.unwrap().unwrap();
    assert_eq!(
        envelope.result,
        Some(json!({ "program_name": "gui_target.exe" }))
    );

    drop(socket);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if state.session(md5).unwrap().status == SessionStatus::Disconnected {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();

    let err = ensure_connected(&state, md5).await.unwrap_err();
    assert!(matches!(
        err.downcast_ref::<DomainError>(),
        Some(DomainError::Disconnected { md5: target }) if target == md5
    ));
    assert!(!state.paths.project_dir(md5).exists());

    server.abort();
    let _ = server.await;
}

/// Makes sure that `ghidra_session attach` with `wait=true` allocates an ID when omitted,
/// waits for `ghidra.ready`, and sends `session.shutdown` on close.
#[tokio::test]
async fn attach_wait_and_close_send_shutdown_and_invalidate_token() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ws_url = format!("ws://{address}{AGENT_WS_PATH}");
    let state = test_state_with_ws_url(root.path(), ws_url);
    std::fs::create_dir_all(&state.paths.tmp_dir).unwrap();
    let uploads = crate::upload::UploadService::new(
        state.clone(),
        [address.to_string(), format!("localhost:{}", address.port())],
        tokio_util::sync::CancellationToken::new(),
    )
    .unwrap();
    let daemon = crate::tools::Daemon {
        state: state.clone(),
        uploads,
        control: crate::tools::Control::default(),
    };
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let attach_task = tokio::spawn(async move {
        let Value::Object(args) = json!({
            "operation": "attach",
            "params": { "wait": true, "timeoutMs": 3000 }
        }) else {
            unreachable!();
        };
        crate::tools::call(&daemon, "ghidra_session", args).await
    });

    let (allocated_md5, token) = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let sessions = state.sessions();
            if let Some(record) = sessions.first() {
                let full = state.session(&record.session_id).unwrap();
                if !full.agent_token.is_empty() {
                    break (full.session_id, full.agent_token);
                }
            }
            notified.await;
        }
    })
    .await
    .unwrap();
    assert_eq!(allocated_md5.len(), 32);

    let mut socket = connect_bridge(address, &token).await;
    send_ws_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "method": "ghidra.ready",
            "params": { "session_id": &allocated_md5, "program_name": "codebrowser.bin" }
        })
        .to_string(),
    )
    .await;

    let (_, result) = attach_task.await.unwrap().unwrap();
    assert_eq!(result["md5"], allocated_md5);
    assert_eq!(result["session"]["status"], "ready");
    assert_eq!(result["session"]["connected"], true);
    assert_eq!(result["session"]["fileName"], "codebrowser.bin");
    assert_eq!(result["job"]["status"], "completed");

    let close_state = state.clone();
    let close_md5 = allocated_md5.clone();
    let close_task = tokio::spawn(async move { close(&close_state, &close_md5, false).await });
    let shutdown_req = recv_ws_text(&mut socket).await;
    assert_eq!(shutdown_req["method"], "session.shutdown");
    let shutdown_id = shutdown_req["id"].as_str().unwrap();
    send_ws_text(
        &mut socket,
        &json!({
            "jsonrpc": "2.0",
            "id": shutdown_id,
            "result": { "closed": true }
        })
        .to_string(),
    )
    .await;
    close_task.await.unwrap().unwrap();

    let closed = state.session(&allocated_md5).unwrap();
    assert_eq!(closed.status, SessionStatus::Closed);
    assert_eq!(closed.agent_token, "");
    let (status_line, _) = upgrade_bridge(address, &token).await;
    assert!(status_line.starts_with("HTTP/1.1 401 "), "{status_line}");
    let _: Map<String, Value> = serde_json::from_value(result).unwrap();

    server.abort();
    let _ = server.await;
}

/// Starts a mock embedded `Bridge.java` WebSocket listener on loopback for `attach_endpoint`.
#[allow(clippy::result_large_err)]
async fn spawn_mock_gui_bridge_server(
    expected_auth: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::Message as WsMsg;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_hdr_async(tcp, |req: &Request, resp: Response| {
            assert_eq!(req.uri().path(), AGENT_WS_PATH);
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|val| val.to_str().ok());
            assert_eq!(auth, Some(expected_auth));
            Ok(resp)
        })
        .await
        .unwrap();
        ws.send(WsMsg::Text(
            json!({
                "jsonrpc": "2.0",
                "method": "ghidra.ready",
                "params": {
                    "session_id": "gui-prog-id",
                    "program_name": "codebrowser_gui.exe"
                }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        for expected_method in ["program.get", "session.shutdown"] {
            let Some(Ok(WsMsg::Text(raw))) = ws.next().await else {
                panic!("expected text request for {expected_method}");
            };
            let req: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(req["method"], expected_method);
            let id = req["id"].as_str().unwrap();
            ws.send(WsMsg::Text(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "program_name": "codebrowser_gui.exe" }
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        }
    });
    (addr, handle)
}

/// Makes sure that `attach_endpoint` validates loopback URLs and connects to an embedded server.
#[tokio::test]
async fn attach_endpoint_connects_to_embedded_gui_server_and_validates_urls() {
    assert!(bridge::parse_gui_ws_url("ws://192.168.1.10:8765/ws/agent").is_err());
    assert!(bridge::parse_gui_ws_url("http://127.0.0.1:8765/ws/agent").is_err());
    assert!(bridge::parse_gui_ws_url("ws://127.0.0.1:8765/ws/agent?token=secret").is_err());

    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path());
    let md5 = "fedcba9876543210fedcba9876543210";
    let (addr, server_task) = spawn_mock_gui_bridge_server("Bearer gui-secret").await;
    let bare_url = format!("ws://127.0.0.1:{}", addr.port());

    let (_, attached) = attach_endpoint(
        &state,
        md5.into(),
        None,
        &bare_url,
        Some("gui-secret"),
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(
        attached["wsUrl"],
        format!("ws://127.0.0.1:{}{AGENT_WS_PATH}", addr.port())
    );
    assert_eq!(attached["bridgeSessionId"], "gui-prog-id");
    assert_eq!(attached["session"]["status"], "ready");
    assert_eq!(attached["session"]["connected"], true);
    assert_eq!(attached["session"]["fileName"], "codebrowser_gui.exe");
    assert_eq!(attached["job"]["status"], "completed");

    let envelope = call(&state, md5, "program.get", json!({})).await.unwrap();
    assert_eq!(
        envelope.result,
        Some(json!({ "program_name": "codebrowser_gui.exe" }))
    );

    close(&state, md5, false).await.unwrap();
    server_task.await.unwrap();
    assert_eq!(state.session(md5).unwrap().status, SessionStatus::Closed);
}
