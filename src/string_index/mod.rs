// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Persistent and in-memory string index snapshots for `ghidra_search strings`.
//!
//! Each binary keeps a snapshot in `projects/<md5>/string-index.json`. The
//! snapshot stores decoded ASCII and UTF-16 string items, `total_indexed`, the
//! bridge `modification_number`, and a deterministic `project_stamp` of
//! `projects/<md5>/ghidra/`. Reopened sessions serve string queries from the
//! snapshot without cold Ghidra scans when the project stamp and session state
//! match. Program mutations, finished auto-analysis jobs, and external project
//! edits invalidate stale snapshots and trigger a fresh rebuild.

mod query;
mod stamp;

pub use stamp::compute_project_stamp;

use crate::error::DomainError;
use crate::model::RpcEnvelope;
use crate::paths::McpPaths;
use crate::session;
use crate::state::McpState;
use crate::string_regexp::RegexError;
use anyhow::Result;
use query::{build_matcher, decode_cursor, evaluate_from_snapshot, parse_string_request};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use stamp::{
    read_raw_disk_snapshot, remove_snapshot_file, updated_stamp_snapshot, write_disk_snapshot,
    SNAPSHOT_VERSION,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Page size used when the daemon hydrates a snapshot from `search.strings`.
const HYDRATE_PAGE_LIMIT: usize = 1000;

/// One cached string entry without raw hex payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedStringItem {
    /// Canonical start address, such as `ram:00401000`.
    pub address: String,
    /// Decoded string text.
    pub value: String,
    /// Byte length of the string in memory.
    pub length: usize,
    /// String character encoding (`ascii`, `utf16le`, or `utf16be`).
    pub encoding: String,
    /// `true` for a defined string data item, `false` for undefined bytes.
    pub defined: bool,
    /// Data type reference of a defined string item, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<Value>,
}

/// Persisted snapshot stored at `projects/<md5>/string-index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringIndexSnapshot {
    /// Snapshot schema version.
    pub version: u32,
    /// Lowercase MD5 of the binary.
    pub md5: String,
    /// Bridge program modification counter captured with this snapshot.
    pub modification_number: i64,
    /// Deterministic stamp of `projects/<md5>/ghidra/` when persisted.
    pub project_stamp: String,
    /// Total cached string count in the bridge index.
    pub total_indexed: usize,
    /// Canonical address-ordered string items.
    pub items: Vec<CachedStringItem>,
}

/// Per-session cache state inside [`StringIndexStore`].
#[derive(Default)]
struct SessionStringEntry {
    /// Hydrated snapshot for the active session, if clean.
    snapshot: Option<Arc<StringIndexSnapshot>>,
    /// `true` after a program mutation or analysis invalidates the snapshot.
    dirty_since_snapshot: bool,
    /// Latest program modification counter observed in the active session.
    known_modification_number: Option<i64>,
}

/// Daemon-wide store for per-session string caches and cursor signatures.
pub struct StringIndexStore {
    /// Per-MD5 cache state. Kept only across short sections that do not block.
    entries: Mutex<HashMap<String, SessionStringEntry>>,
    /// Per-MD5 async lock that puts snapshot hydration for one binary in sequence.
    hydrate_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Ephemeral secret key for opaque pagination cursors.
    cursor_secret: [u8; 32],
}

impl Default for StringIndexStore {
    /// Creates an empty store with a random cursor secret.
    fn default() -> Self {
        let mut secret = [0u8; 32];
        secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self {
            entries: Mutex::new(HashMap::new()),
            hydrate_locks: Mutex::new(HashMap::new()),
            cursor_secret: secret,
        }
    }
}

impl StringIndexStore {
    /// Marks the session index dirty and removes any stale disk snapshot.
    pub fn invalidate_session(&self, paths: &McpPaths, md5: &str) {
        {
            let mut entries = self.entries.lock().expect("string index lock poisoned");
            let entry = entries.entry(md5.to_string()).or_default();
            entry.snapshot = None;
            entry.dirty_since_snapshot = true;
            entry.known_modification_number = None;
        }
        remove_snapshot_file(&paths.string_index_file(md5));
    }

    /// Prepares session cache state when a launch starts.
    ///
    /// A fresh binary import (`existing_project == false`) discards any old
    /// disk snapshot. A saved project launch clears only the in-memory entry
    /// so the reopened session loads and verifies `string-index.json` from disk.
    pub fn on_session_launching(&self, paths: &McpPaths, md5: &str, existing_project: bool) {
        {
            let mut entries = self.entries.lock().expect("string index lock poisoned");
            entries.insert(md5.to_string(), SessionStringEntry::default());
        }
        if !existing_project {
            remove_snapshot_file(&paths.string_index_file(md5));
        }
    }

    /// Refreshes or removes `string-index.json` after `program.save` completes.
    pub fn on_program_saved(&self, paths: &McpPaths, md5: &str) {
        let (snapshot, dirty) = {
            let entries = self.entries.lock().expect("string index lock poisoned");
            match entries.get(md5) {
                Some(entry) => (entry.snapshot.clone(), entry.dirty_since_snapshot),
                None => (None, false),
            }
        };
        if dirty {
            remove_snapshot_file(&paths.string_index_file(md5));
            return;
        }
        let Ok(stamp) = compute_project_stamp(&paths.ghidra_project_root(md5)) else {
            return;
        };
        if let Some(snap) = snapshot {
            let updated = updated_stamp_snapshot(&snap, stamp);
            if write_disk_snapshot(paths, &updated).is_ok() {
                let mut entries = self.entries.lock().expect("string index lock poisoned");
                let entry = entries.entry(md5.to_string()).or_default();
                if !entry.dirty_since_snapshot {
                    entry.snapshot = Some(Arc::new(updated));
                }
            }
        } else if let Some(mut disk) = read_raw_disk_snapshot(paths, md5) {
            disk.project_stamp = stamp;
            let _ = write_disk_snapshot(paths, &disk);
        }
    }

    /// Finalizes snapshot state after `ghidra_session close` stops the bridge.
    ///
    /// When `force` is `false`, `session.shutdown` saves the Ghidra project to
    /// `projects/<md5>/ghidra/`. If no unindexed mutations occurred, the daemon
    /// updates `project_stamp` on `string-index.json` so a reopened session can
    /// serve string queries without a cold scan.
    pub fn on_session_closed(&self, paths: &McpPaths, md5: &str, force: bool) {
        let (snapshot, dirty) = {
            let mut entries = self.entries.lock().expect("string index lock poisoned");
            let previous = entries.remove(md5).unwrap_or_default();
            (previous.snapshot, previous.dirty_since_snapshot)
        };
        if dirty {
            remove_snapshot_file(&paths.string_index_file(md5));
            return;
        }
        if force {
            return;
        }
        let Ok(stamp) = compute_project_stamp(&paths.ghidra_project_root(md5)) else {
            return;
        };
        if let Some(snap) = snapshot {
            let updated = updated_stamp_snapshot(&snap, stamp);
            let _ = write_disk_snapshot(paths, &updated);
        } else if let Some(mut disk) = read_raw_disk_snapshot(paths, md5) {
            disk.project_stamp = stamp;
            let _ = write_disk_snapshot(paths, &disk);
        }
    }

    /// Returns the per-MD5 hydration mutex.
    fn hydrate_lock(&self, md5: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .hydrate_locks
            .lock()
            .expect("hydrate lock map poisoned");
        locks
            .entry(md5.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Returns a verified in-memory or disk snapshot if it matches `current_stamp`.
    fn load_valid_snapshot(
        &self,
        paths: &McpPaths,
        md5: &str,
        current_stamp: &str,
    ) -> Option<Arc<StringIndexSnapshot>> {
        let known_mod = {
            let entries = self.entries.lock().expect("string index lock poisoned");
            if let Some(entry) = entries.get(md5) {
                if entry.dirty_since_snapshot {
                    return None;
                }
                if let Some(snap) = &entry.snapshot {
                    let mod_ok = entry
                        .known_modification_number
                        .is_none_or(|expected| expected == snap.modification_number);
                    if snap.project_stamp == current_stamp && mod_ok {
                        return Some(snap.clone());
                    }
                }
                entry.known_modification_number
            } else {
                None
            }
        };

        let disk = read_raw_disk_snapshot(paths, md5)?;
        let mod_ok = known_mod.is_none_or(|expected| expected == disk.modification_number);
        if disk.project_stamp != current_stamp || !mod_ok {
            return None;
        }
        let arc = Arc::new(disk);
        let mut entries = self.entries.lock().expect("string index lock poisoned");
        let entry = entries.entry(md5.to_string()).or_default();
        if !entry.dirty_since_snapshot {
            entry.known_modification_number = Some(arc.modification_number);
            entry.snapshot = Some(arc.clone());
        }
        Some(arc)
    }

    /// Stores a hydrated snapshot in memory and saves it to disk.
    fn store_hydrated(
        &self,
        paths: &McpPaths,
        snapshot: StringIndexSnapshot,
    ) -> Arc<StringIndexSnapshot> {
        let _ = write_disk_snapshot(paths, &snapshot);
        let md5 = snapshot.md5.clone();
        let mod_num = snapshot.modification_number;
        let arc = Arc::new(snapshot);
        let mut entries = self.entries.lock().expect("string index lock poisoned");
        entries.insert(
            md5,
            SessionStringEntry {
                snapshot: Some(arc.clone()),
                dirty_since_snapshot: false,
                known_modification_number: Some(mod_num),
            },
        );
        arc
    }
}

/// Executes `ghidra_search strings` with daemon snapshot persistence and validation.
///
/// # Errors
///
/// Fails if `params` are invalid, the session cannot connect, or the bridge fails.
pub async fn search_strings(
    state: &Arc<McpState>,
    md5: &str,
    params: Value,
) -> Result<RpcEnvelope> {
    let parsed = parse_string_request(&params)?;
    let matcher = match build_matcher(&parsed) {
        Ok(matcher) => matcher,
        Err(RegexError::Invalid(reason)) => {
            return Err(DomainError::invalid_argument(
                "/filter/regex",
                format!("invalid regular expression: {reason}"),
            )
            .into());
        }
        Err(RegexError::Unsupported) => {
            return session::call(state, md5, "search.strings", params).await;
        }
    };
    if parsed.non_canonical_range {
        return session::call(state, md5, "search.strings", params).await;
    }

    session::ensure_connected(state, md5).await?;
    if state.has_running_analysis(md5) {
        state.string_index.invalidate_session(&state.paths, md5);
        return session::call(state, md5, "search.strings", params).await;
    }

    let resume_after = match &parsed.cursor {
        Some(token) => Some(decode_cursor(
            token,
            md5,
            &parsed.fingerprint,
            &state.string_index.cursor_secret,
        )?),
        None => None,
    };

    let Some(snapshot) = get_or_hydrate_snapshot(state, md5).await? else {
        // Bridge reported `index_complete: false` because analysis runs now.
        return session::call(state, md5, "search.strings", params).await;
    };

    let response = evaluate_from_snapshot(
        &snapshot,
        &parsed,
        &matcher,
        resume_after.as_deref(),
        md5,
        &state.string_index.cursor_secret,
    );
    let mut envelope = RpcEnvelope::response(Uuid::new_v4().to_string(), md5.to_string(), 200);
    envelope.result = Some(response);
    Ok(envelope)
}

/// Returns a verified snapshot from memory or disk, or hydrates one from the bridge.
/// Returns `Ok(None)` when the bridge reports `index_complete: false`.
async fn get_or_hydrate_snapshot(
    state: &Arc<McpState>,
    md5: &str,
) -> Result<Option<Arc<StringIndexSnapshot>>> {
    let stamp = compute_project_stamp(&state.paths.ghidra_project_root(md5))?;
    if let Some(snapshot) = state
        .string_index
        .load_valid_snapshot(&state.paths, md5, &stamp)
    {
        return Ok(Some(snapshot));
    }

    let lock = state.string_index.hydrate_lock(md5);
    let _guard = lock.lock().await;
    let stamp = compute_project_stamp(&state.paths.ghidra_project_root(md5))?;
    if let Some(snapshot) = state
        .string_index
        .load_valid_snapshot(&state.paths, md5, &stamp)
    {
        return Ok(Some(snapshot));
    }

    hydrate_from_bridge(state, md5, stamp).await
}

/// Fetches all cached string pages from the bridge and saves a new snapshot.
/// Returns `Ok(None)` without persistence when `index_complete` is `false`.
async fn hydrate_from_bridge(
    state: &Arc<McpState>,
    md5: &str,
    project_stamp: String,
) -> Result<Option<Arc<StringIndexSnapshot>>> {
    for attempt in 0..2 {
        let mut cursor: Option<String> = None;
        let mut items = Vec::new();
        let mut expected_mod: Option<i64> = None;
        let mut total_indexed = 0usize;
        let mut mod_changed = false;

        loop {
            let mut page_obj = Map::new();
            page_obj.insert("limit".into(), json!(HYDRATE_PAGE_LIMIT));
            if let Some(token) = &cursor {
                page_obj.insert("cursor".into(), json!(token));
            }
            let envelope = session::call(
                state,
                md5,
                "search.strings",
                json!({ "page": Value::Object(page_obj) }),
            )
            .await?;
            let result = envelope.result.ok_or_else(|| DomainError::Internal {
                message: "search.strings response had no result".into(),
            })?;
            let complete = result
                .get("index_complete")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !complete {
                state.string_index.invalidate_session(&state.paths, md5);
                return Ok(None);
            }
            let mod_num = result
                .get("modification_number")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if let Some(prev) = expected_mod {
                if prev != mod_num {
                    mod_changed = true;
                    break;
                }
            } else {
                expected_mod = Some(mod_num);
            }
            total_indexed = usize::try_from(
                result
                    .get("total_indexed")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .unwrap_or(0);
            if let Some(raw_items) = result.get("items").and_then(Value::as_array) {
                for raw in raw_items {
                    let parsed_item: CachedStringItem = serde_json::from_value(raw.clone())
                        .map_err(|err| DomainError::Internal {
                            message: format!("invalid string item from bridge: {err}"),
                        })?;
                    items.push(parsed_item);
                }
            }
            cursor = result
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }

        if mod_changed {
            if attempt == 0 {
                continue;
            }
            return Ok(None);
        }

        let snapshot = StringIndexSnapshot {
            version: SNAPSHOT_VERSION,
            md5: md5.to_string(),
            modification_number: expected_mod.unwrap_or(0),
            project_stamp,
            total_indexed: total_indexed.max(items.len()),
            items,
        };
        return Ok(Some(
            state.string_index.store_hydrated(&state.paths, snapshot),
        ));
    }
    Ok(None)
}
