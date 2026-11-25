// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Concurrency and validation tests for per-MD5 session lifecycle locks.

use super::*;
use crate::bridge::{agent_ws, AGENT_WS_PATH};
use crate::config::McpConfig;
use crate::error::RPC_CODE_INVALID_ARGUMENT;
use crate::state::{test_state, test_state_with_config, ConnectionHandle};
use axum::extract::ws::Message;
use axum::{routing::get, Router};
use std::net::SocketAddr;
use std::sync::Barrier;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

/// Opens an authenticated WebSocket client to `/ws/agent`.
async fn connect_bridge(address: SocketAddr, token: &str) -> TcpStream {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "GET {AGENT_WS_PATH} HTTP/1.1\r\nHost: {address}\r\n\
         Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 101 "), "{line}");
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
    }
    reader.into_inner()
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
