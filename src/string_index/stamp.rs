// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Disk snapshot persistence and Ghidra project stamp calculation.

use super::StringIndexSnapshot;
use crate::paths::{atomic_write, McpPaths};
use anyhow::Result;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Format version of `projects/<md5>/string-index.json`.
pub(super) const SNAPSHOT_VERSION: u32 = 1;
/// Bytes read from `.gbf` buffer headers for `project_stamp`.
const GBF_HEADER_BYTES: usize = 4096;
/// Maximum bytes read from `.gpr` or `.prp` metadata files for `project_stamp`.
const METADATA_READ_LIMIT: u64 = 256 * 1024;

/// Clones `snapshot` with a refreshed `project_stamp`.
pub(super) fn updated_stamp_snapshot(
    snapshot: &StringIndexSnapshot,
    stamp: String,
) -> StringIndexSnapshot {
    let mut clone = snapshot.clone();
    clone.project_stamp = stamp;
    clone
}

/// Reads and validates the structure of `projects/<md5>/string-index.json`.
pub(super) fn read_raw_disk_snapshot(paths: &McpPaths, md5: &str) -> Option<StringIndexSnapshot> {
    let bytes = fs::read(paths.string_index_file(md5)).ok()?;
    let snap: StringIndexSnapshot = serde_json::from_slice(&bytes).ok()?;
    if snap.version != SNAPSHOT_VERSION
        || snap.md5 != md5
        || snap.modification_number < 0
        || snap.total_indexed < snap.items.len()
    {
        return None;
    }
    Some(snap)
}

/// Atomically writes `snapshot` to `projects/<md5>/string-index.json`.
pub(super) fn write_disk_snapshot(paths: &McpPaths, snapshot: &StringIndexSnapshot) -> Result<()> {
    let path = paths.string_index_file(&snapshot.md5);
    let bytes = serde_json::to_vec(snapshot)?;
    atomic_write(&path, &bytes)
}

/// Removes a stale snapshot file if it exists.
pub(super) fn remove_snapshot_file(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Calculates a deterministic digest of persistent files inside `projects/<md5>/ghidra/`.
///
/// The digest covers relative file paths, file sizes, modification timestamps,
/// `.gpr` and `.prp` metadata contents, and `.gbf` buffer headers (`LocalBufferFile`
/// database identifiers and modification parameters). Transient lock files do not
/// change the digest.
///
/// # Errors
///
/// Fails if the directory or metadata of a persistent file cannot be read.
pub fn compute_project_stamp(ghidra_root: &Path) -> Result<String> {
    if !ghidra_root.is_dir() {
        return Ok("empty".to_string());
    }
    let mut files = BTreeMap::new();
    collect_project_files(ghidra_root, ghidra_root, &mut files)?;
    if files.is_empty() {
        return Ok("empty".to_string());
    }
    let mut hasher = md5::Context::new();
    for (rel_path, full_path) in files {
        let meta = match fs::metadata(&full_path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        hasher.consume(rel_path.as_bytes());
        hasher.consume([0]);
        hasher.consume(meta.len().to_le_bytes());
        if let Ok(modified) = meta.modified() {
            if let Ok(since_epoch) = modified.duration_since(UNIX_EPOCH) {
                hasher.consume(since_epoch.as_secs().to_le_bytes());
                hasher.consume(since_epoch.subsec_nanos().to_le_bytes());
            }
        }
        let ext = full_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if (ext.eq_ignore_ascii_case("gpr") || ext.eq_ignore_ascii_case("prp"))
            && meta.len() <= METADATA_READ_LIMIT
        {
            if let Ok(bytes) = fs::read(&full_path) {
                hasher.consume(&bytes);
            }
        } else if ext.eq_ignore_ascii_case("gbf") {
            if let Ok(mut file) = File::open(&full_path) {
                let mut header = [0u8; GBF_HEADER_BYTES];
                if let Ok(read_len) = file.read(&mut header) {
                    hasher.consume(&header[..read_len]);
                }
            }
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Walks `current` and collects persistent regular files keyed by relative path.
fn collect_project_files(
    root: &Path,
    current: &Path,
    out: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if is_transient_project_file(&name_str) {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        if file_type.is_dir() {
            collect_project_files(root, &path, out)?;
        } else if file_type.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                let normalized = rel
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(normalized, path);
            }
        }
    }
    Ok(())
}

/// Returns `true` for Ghidra lock and backup files that change without database edits.
fn is_transient_project_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    Path::new(&lower)
        .extension()
        .is_some_and(|ext| ext == "lock")
        || lower.ends_with(".lock~")
        || lower.ends_with('~')
}

#[cfg(test)]
mod tests {
    use super::super::query::compare_canonical_address;
    use super::*;

    /// Checks project stamp stability against lock files and sensitivity to `.gbf` edits.
    #[test]
    fn project_stamp_ignores_locks_and_detects_project_changes() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra = dir.path().join("ghidra");
        let rep = ghidra.join("project.rep").join("idata").join("00");
        fs::create_dir_all(&rep).unwrap();
        fs::write(ghidra.join("project.gpr"), b"<project/>").unwrap();
        fs::write(rep.join("00000000.prp"), b"STATE=1").unwrap();
        fs::write(rep.join("00000000.gbf"), vec![0x11u8; 512]).unwrap();

        let initial = compute_project_stamp(&ghidra).unwrap();
        fs::write(ghidra.join("project.lock"), b"pid=1").unwrap();
        fs::write(ghidra.join("project.lock~"), b"pid=1").unwrap();
        assert_eq!(compute_project_stamp(&ghidra).unwrap(), initial);

        // External edit inside `.gbf` header changes the stamp at identical file size.
        let mut modified_gbf = vec![0x11u8; 512];
        modified_gbf[24] = 0x99;
        fs::write(rep.join("00000000.gbf"), modified_gbf).unwrap();
        assert_ne!(compute_project_stamp(&ghidra).unwrap(), initial);
    }

    /// Checks canonical address order across 32-bit and 64-bit offsets.
    #[test]
    fn canonical_address_order_handles_wide_offsets() {
        assert!(compare_canonical_address("ram:00401000", "ram:140001000").is_lt());
        assert!(compare_canonical_address("ram:00401000", "ram:00401000").is_eq());
        assert!(compare_canonical_address("ram:00500000", "ram:00401000").is_gt());
    }
}
