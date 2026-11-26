// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of firmware import validation, `.gpr` validation, and GUI session attach.

use super::*;

/// Checks `ghidra_session open` and `ghidra_upload prepare` validation for import and `.gpr` flags.
#[tokio::test]
async fn validates_import_flags_and_gpr_options() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let gpr_dir = root.path().join("sample");
    std::fs::create_dir_all(gpr_dir.join("board.rep")).unwrap();
    let gpr_path = gpr_dir.join("board.gpr");
    std::fs::write(&gpr_path, "<project/>").unwrap();
    let bin_path = root.path().join("fw.bin");
    std::fs::write(&bin_path, [1u8, 2, 3, 4]).unwrap();

    let (_, open_help) = help::run(object(
        json!({ "domain": "ghidra_session", "operation": "open" }),
    ))
    .unwrap();
    for field in [
        "programName",
        "processor",
        "compilerSpec",
        "loader",
        "baseAddress",
        "reimport",
    ] {
        assert!(
            open_help["inputSchema"]["properties"][field].is_object(),
            "absent field {field}"
        );
    }

    let invalid_open_cases = [
        (
            json!({ "path": bin_path, "processor": "invalid" }),
            "processor",
        ),
        (
            json!({ "path": bin_path, "compilerSpec": "default" }),
            "compilerSpec requires processor",
        ),
        (
            json!({ "path": bin_path, "loader": "../BadLoader" }),
            "loader",
        ),
        (
            json!({ "path": bin_path, "baseAddress": "0xZZ" }),
            "baseAddress",
        ),
        (
            json!({ "path": bin_path, "programName": "app" }),
            "programName",
        ),
        (
            json!({ "path": gpr_path, "processor": "ARM:LE:32:Cortex" }),
            "not valid when attaching a .gpr project",
        ),
        (
            json!({ "path": gpr_path, "reimport": true }),
            "not valid when attaching a .gpr project",
        ),
        (
            json!({ "path": gpr_path, "programName": "../escape" }),
            "programName",
        ),
    ];
    for (params, expected) in invalid_open_cases {
        let err = super::super::call(
            &daemon,
            "ghidra_session",
            object(json!({ "operation": "open", "params": params })),
        )
        .await
        .unwrap_err();
        assert!(reason(&err).contains(expected), "{params}: {err:#}");
    }

    let md5 = "0123456789abcdef0123456789abcdef";
    let invalid_upload_cases = [
        (
            json!({ "fileName": "fw.bin", "size": 4, "compilerSpec": "gcc" }),
            "compilerSpec requires processor",
        ),
        (
            json!({ "fileName": "fw.bin", "size": 4, "baseAddress": "-0x100" }),
            "baseAddress",
        ),
        (
            json!({ "fileName": "board.gpr", "size": 4 }),
            ".gpr projects",
        ),
    ];
    for (params, expected) in invalid_upload_cases {
        let err = super::super::call(
            &daemon,
            "ghidra_upload",
            object(json!({ "operation": "prepare", "md5": md5, "params": params })),
        )
        .await
        .unwrap_err();
        assert!(reason(&err).contains(expected), "{params}: {err:#}");
    }
}

/// Makes sure that `ghidra_session attach` validates `path` and skips project copies.
#[tokio::test]
async fn session_attach_validates_target_and_skips_project_copy() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let sample_path = root.path().join("sample.elf");
    let sample_bytes = b"\x7fELFtest";
    std::fs::write(&sample_path, sample_bytes).unwrap();
    let expected_md5 = format!("{:x}", md5::compute(sample_bytes));

    let both_error = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({
            "operation": "attach",
            "md5": expected_md5,
            "params": { "path": sample_path.to_str().unwrap() }
        })),
    )
    .await
    .unwrap_err();
    assert!(
        reason(&both_error).contains("either params.path or md5, not both"),
        "{both_error:#}"
    );

    let (_, attached) = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({
            "operation": "attach",
            "params": { "path": sample_path.to_str().unwrap() }
        })),
    )
    .await
    .unwrap();
    assert_eq!(attached["md5"], expected_md5);
    assert_eq!(attached["sessionId"], expected_md5);
    assert_eq!(attached["session"]["fileName"], "sample.elf");
    assert_eq!(attached["session"]["status"], "starting");
    assert_eq!(attached["session"]["connected"], false);
    assert!(attached["session"].get("token").is_none());

    let bridge_args = attached["bridgeArgs"].as_str().unwrap();
    let token = attached["token"].as_str().unwrap();
    assert!(bridge_args.contains(&format!("session_id={expected_md5}")));
    assert!(bridge_args.contains(&format!("token={token}")));
    assert!(!bridge_args.contains("exit_deadline_sec"));
    assert!(!bridge_args.contains("jar="));
    assert!(!daemon.state.paths.project_dir(&expected_md5).exists());

    let snapshot = std::fs::read_to_string(daemon.state.paths.session_json(&expected_md5)).unwrap();
    assert!(!snapshot.contains(token));
    assert!(!snapshot.contains("agent_token"));

    let url_and_port = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({
            "operation": "attach",
            "params": { "wsUrl": "ws://127.0.0.1:8765/ws/agent", "port": 8765 }
        })),
    )
    .await
    .unwrap_err();
    assert!(
        reason(&url_and_port).contains("either params.wsUrl or params.port, not both"),
        "{url_and_port:#}"
    );

    let orphan_token = super::super::call(
        &daemon,
        "ghidra_session",
        object(json!({
            "operation": "attach",
            "params": { "token": "secret" }
        })),
    )
    .await
    .unwrap_err();
    assert!(
        reason(&orphan_token).contains("requires `params.wsUrl` or `params.port`"),
        "{orphan_token:#}"
    );
}
