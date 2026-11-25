// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of `ghidra_session` checkpoint, reset, and delete operations.

use super::*;

/// Checks `ghidra_help` schemas for `checkpoint.create`, `checkpoint.list`,
/// `checkpoint.restore`, `reset`, and `delete`.
#[test]
fn session_checkpoint_reset_and_delete_help_schemas() {
    let (_, create_help) = help::run(object(json!({
        "domain": "ghidra_session",
        "operation": "checkpoint.create"
    })))
    .expect("checkpoint.create help");
    assert_eq!(create_help["md5"], "required");
    assert!(create_help["inputSchema"]["properties"]["name"].is_object());

    let (_, list_help) = help::run(object(json!({
        "domain": "ghidra_session",
        "operation": "checkpoint.list"
    })))
    .expect("checkpoint.list help");
    assert_eq!(list_help["md5"], "required");
    assert_eq!(list_help["effects"]["read_only"], true);

    let (_, restore_help) = help::run(object(json!({
        "domain": "ghidra_session",
        "operation": "checkpoint.restore"
    })))
    .expect("checkpoint.restore help");
    assert_eq!(restore_help["md5"], "required");
    assert_eq!(restore_help["effects"]["destructive"], true);
    assert!(restore_help["inputSchema"]["properties"]["id"].is_object());

    let (_, reset_help) = help::run(object(json!({
        "domain": "ghidra_session",
        "operation": "reset"
    })))
    .expect("reset help");
    assert_eq!(reset_help["md5"], "required");
    assert_eq!(reset_help["effects"]["destructive"], true);

    let (_, delete_help) = help::run(object(json!({
        "domain": "ghidra_session",
        "operation": "delete"
    })))
    .expect("delete help");
    assert_eq!(delete_help["md5"], "required");
    assert_eq!(delete_help["effects"]["destructive"], true);
}

/// Checks tool calls for `checkpoint.create`, `checkpoint.list`, `reset`, and `delete`,
/// with a mock live bridge that verifies `program.save` and force-stop without save.
#[tokio::test]
async fn session_checkpoint_reset_and_delete_tools_enforce_contracts() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let md5 = "fedcba9876543210fedcba9876543210";
    let project_dir = daemon.state.paths.project_dir(md5);
    let ghidra_dir = daemon.state.paths.ghidra_project_root(md5);
    std::fs::create_dir_all(ghidra_dir.join("project.rep")).unwrap();
    std::fs::write(project_dir.join("binary"), b"\x7fELF").unwrap();
    std::fs::write(
        project_dir.join("binary.json"),
        br#"{"fileName":"app.bin"}"#,
    )
    .unwrap();
    std::fs::write(ghidra_dir.join("project.gpr"), b"before-save").unwrap();
    std::fs::write(ghidra_dir.join("project.rep/data.prp"), b"old").unwrap();

    let mut record =
        crate::model::SessionRecord::launching(md5.into(), "app.bin".into(), "tok".into());
    record.mark_starting();
    record.mark_ready();
    daemon.state.put_session(&record).unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let conn_id = "conn-1".to_string();
    assert!(daemon.state.attach_bridge(
        md5,
        crate::state::ConnectionHandle {
            conn_id: conn_id.clone(),
            sender: tx,
        },
    ));

    let state_for_bridge = daemon.state.clone();
    let ghidra_for_bridge = ghidra_dir.clone();
    let bridge_task = tokio::spawn(async move {
        let Some(axum::extract::ws::Message::Text(wire)) = rx.recv().await else {
            panic!("expected program.save JSON-RPC message");
        };
        let parsed: Value = serde_json::from_str(&wire).expect("jsonrpc wire");
        assert_eq!(parsed["method"], "program.save");
        let req_id = parsed["id"].as_str().expect("id").to_string();
        std::fs::write(ghidra_for_bridge.join("project.gpr"), b"after-save").unwrap();
        let mut env = crate::model::RpcEnvelope::response(req_id.clone(), md5.into(), 200);
        env.result = Some(json!({ "saved": true }));
        state_for_bridge.deliver_response(md5, &conn_id, &req_id, env);
        rx
    });

    let (_, created) = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({
            "operation": "checkpoint.create",
            "md5": md5,
            "params": { "name": "Pre-edit" }
        })),
    )
    .await
    .expect("checkpoint.create");
    let mut rx = bridge_task.await.expect("bridge task");
    assert_eq!(created["saved"], true);
    let cp_id = created["checkpoint"]["id"].as_str().expect("cp id");
    let snap_gpr = daemon
        .state
        .paths
        .checkpoints_dir(md5)
        .join(cp_id)
        .join("ghidra/project.gpr");
    assert_eq!(std::fs::read(snap_gpr).unwrap(), b"after-save");

    let (_, listed) = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({ "operation": "checkpoint.list", "md5": md5 })),
    )
    .await
    .expect("checkpoint.list");
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);

    let (_, reset_res) = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({
            "operation": "reset",
            "md5": md5,
            "params": { "open": false }
        })),
    )
    .await
    .expect("reset");
    assert_eq!(reset_res["reset"], true);
    assert_eq!(reset_res["reopened"], false);
    // Reset must never send `session.shutdown` to the live bridge.
    assert!(rx.try_recv().is_err());
    assert!(project_dir.join("binary").is_file());
    assert!(project_dir.join("binary.json").is_file());
    assert!(!ghidra_dir.exists());
    assert!(!daemon.state.paths.checkpoints_dir(md5).exists());

    let (_, del_res) = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({ "operation": "delete", "md5": md5 })),
    )
    .await
    .expect("delete");
    assert_eq!(del_res["deleted"], true);
    assert!(!project_dir.exists());
    assert!(daemon.state.find_session(md5).is_none());
}

/// Makes sure that checkpoint, reset, and delete calls reject invalid MD5s before
/// lock allocation.
#[tokio::test]
async fn checkpoint_reset_and_delete_reject_invalid_md5_before_lock_allocation() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    for operation in [
        "checkpoint.create",
        "checkpoint.list",
        "checkpoint.restore",
        "reset",
        "delete",
    ] {
        let err = super::super::call(
            &daemon,
            "ghidra_session",
            object(json!({ "operation": operation, "md5": "not-an-md5" })),
        )
        .await
        .unwrap_err();
        assert!(reason(&err).contains("32 hexadecimal"), "{err:#}");
        assert_eq!(daemon.state.lifecycle_lock_count(), 0);
    }
}
