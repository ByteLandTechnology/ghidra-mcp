// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Regression tests for lock-free lifecycle I/O and per-session barriers.

use super::*;
use crate::bridge::{agent_ws, AGENT_WS_PATH};
use crate::config::McpConfig;
use axum::{routing::get, Router};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// Starts an isolated bridge WebSocket listener and fake `analyzeHeadless` launcher.
async fn test_harness(
    root: &Path,
) -> (
    Arc<McpState>,
    SocketAddr,
    PathBuf,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let launcher = write_fake_launcher(root);
    let mut config = McpConfig::default();
    config.ghidra.analyze_headless = Some(launcher.to_string_lossy().into_owned());
    config.timeouts.bridge_disconnect_grace = Duration::from_millis(350);
    config.timeouts.graceful_kill = Duration::from_secs(2);
    config.timeouts.force_kill = Duration::from_secs(1);

    let state =
        crate::state::test_state_with(root, config, format!("ws://{address}{AGENT_WS_PATH}"));
    state.paths.ensure_layout().unwrap();
    bridge::install_runtime(&state.paths.runtime_dir).unwrap();
    let router = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (state, address, launcher, server)
}

/// Writes a fast cross-platform fake `analyzeHeadless` launcher that records each start.
fn write_fake_launcher(root: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = root.join("fake-headless.sh");
        let log = root.join("spawns.log");
        let body = format!(
            "#!/bin/sh\necho \"$2\" >> \"{}\"\nexec sleep 30\n",
            log.display()
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }
    #[cfg(windows)]
    {
        let script = root.join("fake-headless.bat");
        let log = root.join("spawns.log");
        let body = format!(
            "@echo off\r\necho %2>>\"{}\"\r\n\
             powershell -NoProfile -Command \"Start-Sleep -Seconds 30\"\r\n",
            log.display()
        );
        fs::write(&script, body).unwrap();
        script
    }
}

/// Writes a test binary file and returns its path and lowercase MD5.
fn write_binary(root: &Path, name: &str, bytes: &[u8]) -> (PathBuf, String) {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    let md5 = crate::ghidra::file_md5(&path).unwrap();
    (path, md5)
}

/// Connects a raw WebSocket client to `/ws/agent` with `token`.
async fn connect_ws(address: SocketAddr, token: &str) -> TcpStream {
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

/// Sends one masked WebSocket text frame.
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

/// Reads one unmasked server WebSocket text frame.
async fn read_ws_text(socket: &mut TcpStream) -> Option<Value> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await.ok()?;
    if header[0] & 0x0f != 0x01 {
        return None;
    }
    let mut len = usize::from(header[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        socket.read_exact(&mut ext).await.ok()?;
        len = usize::from(u16::from_be_bytes(ext));
    }
    let mut payload = vec![0u8; len];
    socket.read_exact(&mut payload).await.ok()?;
    serde_json::from_slice(&payload).ok()
}

/// Waits until `md5` reaches `Starting` and returns its `agent_token`.
async fn wait_starting_token(state: &McpState, md5: &str) -> String {
    loop {
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(session) = state
            .find_session(md5)
            .filter(|s| s.status == SessionStatus::Starting && !s.agent_token.is_empty())
        {
            return session.agent_token;
        }
        notified.await;
    }
}

/// Sends `ghidra.ready` for `md5` on `socket`.
async fn send_ready(socket: &mut TcpStream, md5: &str) {
    send_ws_text(
        socket,
        &json!({
            "jsonrpc": "2.0",
            "method": "ghidra.ready",
            "params": { "session_id": md5, "program_name": "test.bin" }
        })
        .to_string(),
    )
    .await;
}

/// Waits for `md5` to enter a launch state with a fresh token, then completes `ghidra.ready`.
async fn accept_launch_handshake(state: &McpState, address: SocketAddr, md5: &str) -> TcpStream {
    let token = loop {
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(session) = state
            .find_session(md5)
            .filter(|s| s.status.is_launching() && !s.agent_token.is_empty())
        {
            break session.agent_token;
        }
        notified.await;
    };
    let mut socket = connect_ws(address, &token).await;
    send_ready(&mut socket, md5).await;
    socket
}

/// Verifies Binary B completes `session::open` and `bridge::handshake` under 50 ms
/// while Binary A closes gracefully.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_session_open_and_handshake_stay_under_50ms_during_graceful_close() {
    let root = tempfile::tempdir().unwrap();
    let (state, address, _, server) = test_harness(root.path()).await;
    let (path_a, md5_a) = write_binary(root.path(), "a.bin", b"binary-a");
    let (path_reuse, md5_reuse) = write_binary(root.path(), "reuse.bin", b"binary-reuse");
    let (path_b, md5_b) = write_binary(root.path(), "b.bin", b"binary-b");
    persist_binary(&state.paths, &path_b, &md5_b, "b.bin").unwrap();

    let (open_a, mut sock_a) = tokio::join!(
        open(
            &state,
            md5_a.clone(),
            Some(&path_a),
            Some(Duration::from_secs(5))
        ),
        accept_launch_handshake(&state, address, &md5_a)
    );
    open_a.unwrap();
    let (open_r, _sock_r) = tokio::join!(
        open(
            &state,
            md5_reuse.clone(),
            Some(&path_reuse),
            Some(Duration::from_secs(5))
        ),
        accept_launch_handshake(&state, address, &md5_reuse)
    );
    open_r.unwrap();

    let shutdown_seen = Arc::new(tokio::sync::Notify::new());
    let shutdown_seen_bg = shutdown_seen.clone();
    let bridge_a = tokio::spawn(async move {
        let req = read_ws_text(&mut sock_a).await.unwrap();
        assert_eq!(req["method"], "session.shutdown");
        shutdown_seen_bg.notify_waiters();
        tokio::time::sleep(Duration::from_millis(600)).await;
        send_ws_text(
            &mut sock_a,
            &json!({"jsonrpc": "2.0", "id": req["id"], "result": {"ok": true}}).to_string(),
        )
        .await;
    });

    let close_state = state.clone();
    let close_md5 = md5_a.clone();
    let close_task = tokio::spawn(async move { close(&close_state, &close_md5, false).await });
    shutdown_seen.notified().await;

    let lock_start = Instant::now();
    drop(state.lifecycle_lock.lock().await);
    assert!(lock_start.elapsed() < Duration::from_millis(5));

    let reuse_start = Instant::now();
    let (_, reuse_val) = open(&state, md5_reuse, None, Some(Duration::from_secs(1)))
        .await
        .unwrap();
    let reuse_elapsed = reuse_start.elapsed();
    assert_eq!(reuse_val["reused"], true);
    assert!(
        reuse_elapsed < Duration::from_millis(50),
        "reuse took {reuse_elapsed:?}"
    );

    let open_start = Instant::now();
    let (_, open_b_val) = open(&state, md5_b.clone(), None, None).await.unwrap();
    let open_elapsed = open_start.elapsed();
    assert!(
        open_elapsed < Duration::from_millis(50),
        "session::open took {open_elapsed:?}"
    );
    let job_id = open_b_val["jobId"].as_str().unwrap().to_string();
    let token_b = wait_starting_token(&state, &md5_b).await;
    let mut sock_b = connect_ws(address, &token_b).await;
    assert!(!close_task.is_finished());

    let handshake_start = Instant::now();
    send_ready(&mut sock_b, &md5_b).await;
    let job = state
        .await_job(&job_id, Some(Duration::from_secs(2)))
        .await
        .unwrap();
    let handshake_elapsed = handshake_start.elapsed();
    assert_eq!(job.status, JobStatus::Completed);
    assert_eq!(state.session(&md5_b).unwrap().status, SessionStatus::Ready);
    assert!(
        handshake_elapsed < Duration::from_millis(50),
        "bridge::handshake took {handshake_elapsed:?}"
    );
    assert!(!close_task.is_finished());

    bridge_a.await.unwrap();
    close_task.await.unwrap().unwrap();
    assert_eq!(state.session(&md5_a).unwrap().status, SessionStatus::Closed);
    state.stop_all().await;
    server.abort();
}

/// Verifies four concurrent `on_disconnect` events reap their process trees in parallel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_concurrent_disconnects_reap_processes_in_parallel() {
    let root = tempfile::tempdir().unwrap();
    let (state, address, _, server) = test_harness(root.path()).await;
    let mut sockets = Vec::new();
    let mut md5s = Vec::new();

    for index in 0..4 {
        let name = format!("bin-{index}.bin");
        let (path, md5) = write_binary(root.path(), &name, name.as_bytes());
        let (opened, sock) = tokio::join!(
            open(
                &state,
                md5.clone(),
                Some(&path),
                Some(Duration::from_secs(5))
            ),
            accept_launch_handshake(&state, address, &md5)
        );
        opened.unwrap();
        md5s.push(md5);
        sockets.push(sock);
    }

    let start = Instant::now();
    drop(sockets);
    for md5 in &md5s {
        loop {
            let notified = state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let disconnected = state
                .session(md5)
                .is_ok_and(|s| s.status == SessionStatus::Disconnected);
            if disconnected && !state.has_teardown(md5) {
                break;
            }
            notified.await;
        }
    }
    let elapsed = start.elapsed();
    // Each disconnect waits 350 ms grace before termination; serial execution takes >= 1400 ms.
    assert!(elapsed >= Duration::from_millis(340), "elapsed {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(1000),
        "disconnect reaps ran serially: {elapsed:?}"
    );
    server.abort();
}

/// Verifies a concurrent relaunch on Binary A waits outside `lifecycle_lock`
/// for Binary A teardown before it spawns a new JVM.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_md5_relaunch_waits_outside_lock_for_teardown() {
    let root = tempfile::tempdir().unwrap();
    let (state, address, _, server) = test_harness(root.path()).await;
    let spawns_log = root.path().join("spawns.log");
    let (path_a, md5_a) = write_binary(root.path(), "same-a.bin", b"same-binary-a");
    let (path_b, md5_b) = write_binary(root.path(), "other-b.bin", b"other-binary-b");

    let (open_a, sock_a) = tokio::join!(
        open(
            &state,
            md5_a.clone(),
            Some(&path_a),
            Some(Duration::from_secs(5))
        ),
        accept_launch_handshake(&state, address, &md5_a)
    );
    open_a.unwrap();
    let (open_b, _sock_b) = tokio::join!(
        open(
            &state,
            md5_b.clone(),
            Some(&path_b),
            Some(Duration::from_secs(5))
        ),
        accept_launch_handshake(&state, address, &md5_b)
    );
    open_b.unwrap();
    let baseline_spawns = fs::read_to_string(&spawns_log).unwrap().lines().count();
    assert_eq!(baseline_spawns, 2);

    // Drop Binary A's bridge socket so `on_disconnect` enters its 350 ms process teardown.
    drop(sock_a);
    loop {
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if state.session(&md5_a).unwrap().status == SessionStatus::Disconnected
            && state.has_teardown(&md5_a)
        {
            break;
        }
        notified.await;
    }

    let relaunch_state = state.clone();
    let relaunch_md5 = md5_a.clone();
    let spawn_seen = Arc::new(AtomicUsize::new(0));
    let spawn_seen_bg = spawn_seen.clone();
    let relaunch_log = spawns_log.clone();
    let relaunch = tokio::spawn(async move {
        let res = open(
            &relaunch_state,
            relaunch_md5,
            None,
            Some(Duration::from_secs(5)),
        )
        .await;
        spawn_seen_bg.store(
            fs::read_to_string(&relaunch_log).unwrap().lines().count(),
            Ordering::SeqCst,
        );
        res
    });

    tokio::time::sleep(Duration::from_millis(80)).await;
    // Teardown still runs: no second JVM spawned for Binary A yet.
    assert!(state.has_teardown(&md5_a));
    assert_eq!(fs::read_to_string(&spawns_log).unwrap().lines().count(), 2);

    // Meanwhile Binary B stays unblocked and `lifecycle_lock` is free.
    let b_start = Instant::now();
    let (_, b_reuse) = open(&state, md5_b, None, Some(Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(b_reuse["reused"], true);
    assert!(b_start.elapsed() < Duration::from_millis(25));

    let _sock_a2 = accept_launch_handshake(&state, address, &md5_a).await;
    relaunch.await.unwrap().unwrap();
    assert_eq!(spawn_seen.load(Ordering::SeqCst), 3);
    assert_eq!(state.session(&md5_a).unwrap().status, SessionStatus::Ready);
    state.stop_all().await;
    server.abort();
}

/// Verifies a launch cancelled by `close` reaps its child and preserves `Killed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reaps_superseded_child_when_closed_during_launch() {
    let root = tempfile::tempdir().unwrap();
    let (state, _address, _, server) = test_harness(root.path()).await;
    let (path_a, md5_a) = write_binary(root.path(), "cancel.bin", b"cancel-launch");

    let (_, opened) = open(&state, md5_a.clone(), Some(&path_a), None)
        .await
        .unwrap();
    let job_id = opened["jobId"].as_str().unwrap().to_string();

    close(&state, &md5_a, true).await.unwrap();
    assert!(!state.has_teardown(&md5_a));
    assert_eq!(state.session(&md5_a).unwrap().status, SessionStatus::Killed);
    assert_eq!(state.job(&job_id).unwrap().status, JobStatus::Failed);
    let err = state
        .await_job(&job_id, Some(Duration::from_millis(50)))
        .await
        .unwrap_err();
    assert!(matches!(
        DomainError::from_error(&err),
        DomainError::Disconnected { .. }
    ));
    server.abort();
}

/// Verifies a failed launch releases its transition so a later `open` succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovers_after_failed_launch_when_launcher_restored() {
    let root = tempfile::tempdir().unwrap();
    let (state, address, launcher, server) = test_harness(root.path()).await;
    let (path_a, md5_a) = write_binary(root.path(), "recover.bin", b"recover-launch");
    let backup = root.path().join("launcher.bak");
    fs::rename(&launcher, &backup).unwrap();

    let err = open(
        &state,
        md5_a.clone(),
        Some(&path_a),
        Some(Duration::from_secs(2)),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("failed") || err.to_string().contains("Headless"));
    assert_eq!(state.session(&md5_a).unwrap().status, SessionStatus::Error);

    fs::rename(&backup, &launcher).unwrap();
    let (reopened, _sock) = tokio::join!(
        open(&state, md5_a.clone(), None, Some(Duration::from_secs(5))),
        accept_launch_handshake(&state, address, &md5_a)
    );
    reopened.unwrap();
    assert_eq!(state.session(&md5_a).unwrap().status, SessionStatus::Ready);
    state.stop_all().await;
    server.abort();
}
