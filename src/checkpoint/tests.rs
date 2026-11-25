// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Unit tests for persistent project checkpoints, project resets, and session deletion.

use super::{
    create_checkpoint, list_checkpoints, resolve_checkpoint, restore_checkpoint,
    validate_checkpoint_id,
};
use crate::config::McpConfig;
use crate::paths::McpPaths;
use crate::project::{delete_project, reset_project};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Sample MD5 digest for test fixtures.
const TEST_MD5: &str = "0123456789abcdef0123456789abcdef";

/// Builds test `McpPaths` inside `root`.
fn test_paths(root: &Path) -> McpPaths {
    let home = root.join("home");
    let runtime_dir = root.join("run");
    McpPaths {
        config_toml: home.join("config.toml"),
        projects_dir: home.join("projects"),
        tmp_dir: runtime_dir.join("tmp"),
        runtime_dir,
    }
}

/// Builds test `McpPaths` inside `root` and prepares a saved project fixture.
fn setup_saved_project(root: &Path) -> McpPaths {
    let paths = test_paths(root);
    paths.ensure_layout().expect("layout");
    let project_dir = paths.project_dir(TEST_MD5);
    let ghidra_dir = paths.ghidra_project_root(TEST_MD5);
    let rep_dir = ghidra_dir.join("project.rep").join("idata");
    fs::create_dir_all(&rep_dir).expect("rep dir");
    fs::write(project_dir.join("binary"), b"\x7fELFtest").expect("binary");
    fs::write(
        project_dir.join("binary.json"),
        br#"{"fileName":"sample.elf"}"#,
    )
    .expect("binary.json");
    fs::write(ghidra_dir.join("project.gpr"), b"gpr-v1").expect("project.gpr");
    fs::write(rep_dir.join("00000000.prp"), b"state-v1").expect("prp");
    fs::write(ghidra_dir.join("project.rep").join("project.lock"), b"lock").expect("lock");
    fs::write(
        ghidra_dir.join("project.rep").join("project.lock~"),
        b"lock-backup",
    )
    .expect("lock~");
    paths
}

/// Checks that `create_checkpoint` copies `project.gpr` and `project.rep/`, skips `.lock`
/// files, and clears `.pending-*` directories.
#[test]
fn create_checkpoint_skips_locks_and_cleans_pending_dirs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = setup_saved_project(temp.path());
    let stale_pending = paths.checkpoints_dir(TEST_MD5).join(".pending-stale");
    fs::create_dir_all(&stale_pending).expect("stale pending");
    fs::write(stale_pending.join("partial"), b"bad").expect("partial");

    let outcome = create_checkpoint(&paths, TEST_MD5, Some("Initial import".into()), 5)
        .expect("create checkpoint");
    assert_eq!(outcome.retained_count, 1);
    assert_eq!(outcome.evicted_ids, Vec::<String>::new());
    assert_eq!(outcome.checkpoint.name.as_deref(), Some("Initial import"));
    assert!(!stale_pending.exists());

    let snap_ghidra = paths
        .checkpoints_dir(TEST_MD5)
        .join(&outcome.checkpoint.id)
        .join("ghidra");
    assert_eq!(
        fs::read(snap_ghidra.join("project.gpr")).expect("gpr"),
        b"gpr-v1"
    );
    assert_eq!(
        fs::read(snap_ghidra.join("project.rep/idata/00000000.prp")).expect("prp"),
        b"state-v1"
    );
    assert!(!snap_ghidra.join("project.rep/project.lock").exists());
    assert!(!snap_ghidra.join("project.rep/project.lock~").exists());
}

/// Checks that `create_checkpoint` enforces `max_per_binary` and evicts the oldest snapshots.
#[test]
fn retention_cap_evicts_oldest_checkpoints() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = setup_saved_project(temp.path());

    let first = create_checkpoint(&paths, TEST_MD5, Some("cp-1".into()), 2).expect("cp 1");
    thread::sleep(Duration::from_millis(5));
    let second = create_checkpoint(&paths, TEST_MD5, Some("cp-2".into()), 2).expect("cp 2");
    thread::sleep(Duration::from_millis(5));
    let third = create_checkpoint(&paths, TEST_MD5, Some("cp-3".into()), 2).expect("cp 3");

    assert_eq!(third.retained_count, 2);
    assert_eq!(third.evicted_ids, vec![first.checkpoint.id.clone()]);
    assert!(!paths
        .checkpoints_dir(TEST_MD5)
        .join(&first.checkpoint.id)
        .exists());

    let listed = list_checkpoints(&paths, TEST_MD5).expect("list");
    let ids: Vec<&str> = listed.iter().map(|item| item.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![third.checkpoint.id.as_str(), second.checkpoint.id.as_str()]
    );
}

/// Checks `resolve_checkpoint` by ID, by name, and with no selector, plus `restore_checkpoint`.
#[test]
fn resolve_and_restore_replace_ghidra_tree_atomically() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = setup_saved_project(temp.path());
    let first = create_checkpoint(&paths, TEST_MD5, Some("Before rename".into()), 5).expect("cp 1");
    thread::sleep(Duration::from_millis(5));

    let ghidra_dir = paths.ghidra_project_root(TEST_MD5);
    fs::write(ghidra_dir.join("project.gpr"), b"gpr-v2").expect("mutate gpr");
    fs::write(
        ghidra_dir.join("project.rep/idata/00000000.prp"),
        b"state-v2",
    )
    .expect("mutate prp");
    fs::write(ghidra_dir.join("project.rep/extra.dat"), b"extra").expect("extra");

    let second = create_checkpoint(&paths, TEST_MD5, Some("After rename".into()), 5).expect("cp 2");

    let latest = resolve_checkpoint(&paths, TEST_MD5, None, None).expect("latest");
    assert_eq!(latest.id, second.checkpoint.id);
    let by_name =
        resolve_checkpoint(&paths, TEST_MD5, None, Some("Before rename")).expect("by name");
    assert_eq!(by_name.id, first.checkpoint.id);
    assert!(resolve_checkpoint(&paths, TEST_MD5, Some("a"), Some("b")).is_err());
    assert!(resolve_checkpoint(&paths, TEST_MD5, None, Some("   ")).is_err());
    assert!(validate_checkpoint_id("../bad").is_err());

    // Simulate an interrupted swap where `ghidra/` moved to `.ghidra-old-*` and the target ID
    // does not exist: `restore_checkpoint` must put `.ghidra-old-*` back at `ghidra/`.
    let interrupted = paths.project_dir(TEST_MD5).join(".ghidra-old-interrupted");
    fs::rename(&ghidra_dir, &interrupted).expect("simulate interrupted swap");
    assert!(restore_checkpoint(&paths, TEST_MD5, "missing-id").is_err());
    assert!(ghidra_dir.join("project.gpr").is_file());
    assert!(!interrupted.exists());

    let restored =
        restore_checkpoint(&paths, TEST_MD5, &first.checkpoint.id).expect("restore first");
    assert_eq!(restored.id, first.checkpoint.id);
    assert_eq!(
        fs::read(ghidra_dir.join("project.gpr")).expect("restored gpr"),
        b"gpr-v1"
    );
    assert_eq!(
        fs::read(ghidra_dir.join("project.rep/idata/00000000.prp")).expect("restored prp"),
        b"state-v1"
    );
    assert!(!ghidra_dir.join("project.rep/extra.dat").exists());
    // The checkpoint stays intact on disk so callers can restore it again.
    assert!(paths
        .checkpoints_dir(TEST_MD5)
        .join(&first.checkpoint.id)
        .join("checkpoint.json")
        .is_file());
}

/// Checks `reset_project` and `delete_project` directory invariants.
#[test]
fn reset_keeps_binary_while_delete_removes_all_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = setup_saved_project(temp.path());
    create_checkpoint(&paths, TEST_MD5, Some("cp".into()), 5).expect("checkpoint");
    let recovery_dir = paths.project_dir(TEST_MD5).join("recovery-backups/snap1");
    fs::create_dir_all(&recovery_dir).expect("recovery");
    fs::create_dir_all(paths.session_dir(TEST_MD5)).expect("session dir");
    fs::write(paths.session_json(TEST_MD5), b"{}").expect("session.json");
    fs::create_dir_all(paths.log_dir(TEST_MD5)).expect("log dir");
    fs::write(paths.stdout_log(TEST_MD5), b"stdout").expect("stdout.log");

    let file_name = reset_project(&paths, TEST_MD5).expect("reset_project");
    assert_eq!(file_name, "sample.elf");
    let project_dir = paths.project_dir(TEST_MD5);
    assert!(project_dir.join("binary").is_file());
    assert!(project_dir.join("binary.json").is_file());
    assert!(!paths.ghidra_project_root(TEST_MD5).exists());
    assert!(!paths.checkpoints_dir(TEST_MD5).exists());
    assert!(!project_dir.join("recovery-backups").exists());

    assert!(delete_project(&paths, TEST_MD5).expect("delete_project"));
    assert!(!project_dir.exists());
    assert!(!paths.session_dir(TEST_MD5).exists());
    assert!(!paths.log_dir(TEST_MD5).exists());
    assert!(!delete_project(&paths, TEST_MD5).expect("idempotent delete"));
}

/// Checks `[checkpoints].max_per_binary` in `config.toml`.
#[test]
fn config_parses_checkpoint_cap_and_rejects_zero() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = test_paths(temp.path());
    let default_cfg = McpConfig::load_or_create(&paths).expect("default config");
    assert_eq!(default_cfg.checkpoints.max_per_binary, 10);

    fs::write(&paths.config_toml, "[checkpoints]\nmax_per_binary = 4\n").expect("write 4");
    let custom_cfg = McpConfig::load_or_create(&paths).expect("custom config");
    assert_eq!(custom_cfg.checkpoints.max_per_binary, 4);

    fs::write(&paths.config_toml, "[checkpoints]\nmax_per_binary = 0\n").expect("write 0");
    assert!(McpConfig::load_or_create(&paths).is_err());
}
