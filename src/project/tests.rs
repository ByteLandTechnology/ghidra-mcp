// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Unit tests for firmware binary persistence, `.gpr` attachment, reset, and deletion.

use super::*;
use crate::checkpoint::{create_checkpoint, list_checkpoints, restore_checkpoint};
use std::collections::BTreeMap;
use std::time::SystemTime;

/// Builds isolated [`McpPaths`] inside `root` without hidden segments.
fn test_paths(root: &Path) -> McpPaths {
    let paths = McpPaths {
        config_toml: root.join("config.toml"),
        projects_dir: root.join("projects"),
        runtime_dir: root.join("run"),
        tmp_dir: root.join("run").join("tmp"),
    };
    paths.ensure_layout().unwrap();
    paths
}

/// Collects file sizes and modification timestamps across `dir`.
fn snapshot_tree(dir: &Path) -> BTreeMap<PathBuf, (u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
            } else {
                out.insert(path, (meta.len(), meta.modified().unwrap()));
            }
        }
    }
    out
}

/// Checks that firmware extensions remain on the import path and options persist.
#[test]
fn keeps_sanitized_firmware_extensions_and_options() {
    let root = tempfile::tempdir().unwrap();
    let paths = test_paths(root.path());
    for (index, file_name, expected_ext, expected_loader) in [
        (1u8, "STM32.BIN", "binary.bin", None),
        (2u8, "boot.HEX", "binary.hex", None),
        (3u8, "app.IHEX", "binary.ihex", None),
        (
            4u8,
            "motorola.SREC",
            "binary.srec",
            Some("MotorolaHexLoader"),
        ),
        (5u8, "app.elf", "binary", None),
    ] {
        let bytes = [index; 16];
        let md5 = format!("{:x}", md5::compute(bytes));
        let source = root.path().join(file_name);
        fs::write(&source, bytes).unwrap();
        let opts = ImportOptions::from_raw(
            Some("ARM:LE:32:Cortex"),
            Some("default"),
            None,
            Some("08000000"),
        )
        .unwrap();
        persist_binary_with_options(&paths, &source, &md5, file_name, &opts, false).unwrap();
        let prepared = prepare_project(&paths, &md5).unwrap();
        let LaunchMode::ImportBinary {
            input_path,
            options,
        } = prepared.launch_mode
        else {
            panic!("expected ImportBinary mode");
        };
        assert_eq!(
            input_path.file_name().unwrap().to_str().unwrap(),
            expected_ext
        );
        assert_eq!(options.processor.as_deref(), Some("ARM:LE:32:Cortex"));
        assert_eq!(options.compiler_spec.as_deref(), Some("default"));
        assert_eq!(options.base_address.as_deref(), Some("0x08000000"));
        assert_eq!(options.effective_loader(&input_path), expected_loader);
    }

    let lebe = ImportOptions::from_raw(
        Some("ARM:LEBE:32:v8LEInstruction"),
        None,
        Some("ghidra.app.util.opinion.BinaryLoader"),
        Some("ram:08004000"),
    )
    .unwrap();
    assert_eq!(
        lebe.processor.as_deref(),
        Some("ARM:LEBE:32:v8LEInstruction")
    );
    assert_eq!(lebe.loader.as_deref(), Some("BinaryLoader"));
    assert_eq!(lebe.base_address.as_deref(), Some("ram:0x08004000"));

    let saved_md5 = format!("{:x}", md5::compute([9u8; 16]));
    let saved_src = root.path().join("saved.bin");
    fs::write(&saved_src, [9u8; 16]).unwrap();
    let initial =
        ImportOptions::from_raw(Some("ARM:LE:32:Cortex"), None, None, Some("08000000")).unwrap();
    persist_binary_with_options(&paths, &saved_src, &saved_md5, "saved.bin", &initial, false)
        .unwrap();
    let ghidra_root = paths.ghidra_project_root(&saved_md5);
    fs::create_dir_all(ghidra_root.join("project.rep")).unwrap();
    fs::write(ghidra_root.join("project.gpr"), "<project/>").unwrap();

    let conflicting =
        ImportOptions::from_raw(Some("ARM:LE:32:Cortex"), None, None, Some("08004000")).unwrap();
    let conflict_err =
        update_binary_import_options(&paths, &saved_md5, &conflicting, false).unwrap_err();
    assert!(conflict_err.to_string().contains("reimport=true"));
    update_binary_import_options(&paths, &saved_md5, &conflicting, true).unwrap();
}

/// Checks deterministic 32-hex `.gpr` IDs, non-hidden aliases, and zero-mutation lock errors.
#[test]
fn attaches_hidden_gpr_and_rejects_locked_project_without_changes() {
    let root = tempfile::tempdir().unwrap();
    let paths = test_paths(root.path());
    let hidden_dir = root.path().join(".hidden-ghidra").join("board");
    fs::create_dir_all(hidden_dir.join("firmware.rep")).unwrap();
    let gpr_file = hidden_dir.join("firmware.gpr");
    fs::write(&gpr_file, "<project/>").unwrap();

    let gpr_first = resolve_gpr_path(&gpr_file).unwrap();
    let gpr_second = resolve_gpr_path(&gpr_file).unwrap();
    assert_eq!(gpr_first.md5, gpr_second.md5);
    assert_eq!(gpr_first.md5.len(), 32);
    assert!(gpr_first.md5.bytes().all(|b| b.is_ascii_hexdigit()));

    persist_attached_gpr(&paths, &gpr_first, Some("bootloader")).unwrap();
    let prepared = prepare_project(&paths, &gpr_first.md5).unwrap();
    #[cfg(unix)]
    {
        for part in prepared.ghidra_launch_root.components() {
            if let std::path::Component::Normal(segment) = part {
                assert!(
                    !segment.to_string_lossy().starts_with('.'),
                    "launch path has hidden segment: {}",
                    prepared.ghidra_launch_root.display()
                );
            }
        }
    }
    assert_eq!(prepared.ghidra_project_name, "firmware");

    // Place a Ghidra `.lock` file and verify zero project file mutations on lock rejection.
    let lock_path = hidden_dir.join("firmware.lock");
    fs::write(&lock_path, "Project lock").unwrap();
    let before = snapshot_tree(&hidden_dir);
    let err = check_gpr_not_locked(&gpr_first).unwrap_err();
    assert!(err.to_string().contains("locked"), "{err}");
    let after = snapshot_tree(&hidden_dir);
    assert_eq!(before, after);
}

/// Checks that `reset_project` keeps firmware extensions and rejects attached `.gpr` sessions,
/// and that `delete_project` removes `.gpr` aliases without changes to external project files.
#[test]
fn reset_preserves_firmware_extension_and_delete_preserves_external_gpr() {
    let root = tempfile::tempdir().unwrap();
    let paths = test_paths(root.path());
    let srec_bytes = [7u8; 16];
    let srec_md5 = format!("{:x}", md5::compute(srec_bytes));
    let srec_src = root.path().join("image.SREC");
    fs::write(&srec_src, srec_bytes).unwrap();
    let opts =
        ImportOptions::from_raw(Some("ARM:LE:32:Cortex"), None, None, Some("08000000")).unwrap();
    persist_binary_with_options(&paths, &srec_src, &srec_md5, "image.SREC", &opts, true).unwrap();
    let ghidra_dir = paths.ghidra_project_root(&srec_md5);
    fs::create_dir_all(ghidra_dir.join("project.rep")).unwrap();
    fs::write(ghidra_dir.join("project.gpr"), b"gpr").unwrap();
    create_checkpoint(&paths, &srec_md5, Some("cp".into()), 5).unwrap();

    assert_eq!(reset_project(&paths, &srec_md5).unwrap(), "image.SREC");
    assert!(paths.project_dir(&srec_md5).join("binary.srec").is_file());
    assert!(!is_reimport_pending(&paths, &srec_md5).unwrap());
    assert!(!ghidra_dir.exists());

    let ext_dir = root.path().join("external");
    fs::create_dir_all(ext_dir.join("mcu.rep")).unwrap();
    let gpr_path = ext_dir.join("mcu.gpr");
    fs::write(&gpr_path, b"<project/>").unwrap();
    let gpr = resolve_gpr_path(&gpr_path).unwrap();
    persist_attached_gpr(&paths, &gpr, None).unwrap();
    let _prepared = prepare_project(&paths, &gpr.md5).unwrap();

    assert!(ensure_resettable_binary(&paths, &gpr.md5).is_err());
    assert!(reset_project(&paths, &gpr.md5).is_err());
    assert!(create_checkpoint(&paths, &gpr.md5, None, 5).is_err());
    assert!(list_checkpoints(&paths, &gpr.md5).is_err());
    assert!(restore_checkpoint(&paths, &gpr.md5, "cp").is_err());

    assert!(delete_project(&paths, &gpr.md5).unwrap());
    assert!(!paths.project_dir(&gpr.md5).exists());
    #[cfg(unix)]
    assert!(fs::symlink_metadata(paths.attached_dir().join(&gpr.md5)).is_err());
    assert!(gpr_path.is_file());
    assert!(ext_dir.join("mcu.rep").is_dir());
}
