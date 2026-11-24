// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Bounded call-graph and basic-block graph queries that run in the daemon.
//!
//! Each graph operation combines bridge methods through `batch.execute` so
//! callers do not make one round-trip for each function or instruction.

mod basic_blocks;
mod callgraph;

pub(crate) use basic_blocks::{run_basic_blocks, schema as basic_blocks_schema};
pub(crate) use callgraph::{run_callgraph, schema as callgraph_schema};

use crate::error::DomainError;
use crate::model::RpcError;
use crate::session;
use crate::state::McpState;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

/// Maximum number of items in one `batch.execute` request (`ApiRegistry.MAX_BATCH_ITEMS`).
pub(super) const MAX_BATCH_ITEMS: usize = 1000;

/// Maximum page size of bridge list methods (`Page.MAX_LIMIT`).
pub(super) const MAX_PAGE_LIMIT: usize = 1000;

/// One sub-request inside a `batch.execute` call.
#[derive(Clone, Debug)]
pub(super) struct BatchItem {
    /// Correlation identifier within the batch chunk.
    pub id: String,
    /// Bridge method name, such as `function_call.list`.
    pub method: &'static str,
    /// Method arguments object.
    pub arguments: Value,
}

/// The result or bridge error of one item in `batch.execute`.
#[derive(Clone, Debug)]
pub(super) enum BatchOutcome {
    /// Successful sub-request payload.
    Ok(Value),
    /// Per-item bridge failure.
    Err {
        /// HTTP-like status code from the bridge error.
        status: Option<i32>,
        /// Structured bridge error record.
        error: RpcError,
    },
}

/// Parsed canonical address components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ParsedAddress {
    /// Address space name, such as `ram` or `EXTERNAL`.
    pub space: String,
    /// Unsigned 64-bit byte offset in `space`.
    pub offset: u64,
    /// Normalized `space:offset` identifier.
    pub canonical: String,
}

/// Sends `items` through `batch.execute` in chunks of at most [`MAX_BATCH_ITEMS`].
pub(super) async fn execute_batch(
    state: &Arc<McpState>,
    md5: &str,
    items: &[BatchItem],
) -> Result<BTreeMap<String, BatchOutcome>> {
    let mut outcomes = BTreeMap::new();
    if items.is_empty() {
        return Ok(outcomes);
    }
    for chunk in items.chunks(MAX_BATCH_ITEMS) {
        let wire_items: Vec<Value> = chunk
            .iter()
            .map(|item| {
                json!({
                    "id": item.id,
                    "method": item.method,
                    "arguments": item.arguments,
                })
            })
            .collect();
        let envelope = session::call(
            state,
            md5,
            "batch.execute",
            json!({
                "transaction_mode": "per_item",
                "items": wire_items,
            }),
        )
        .await?;
        let response = envelope.result.ok_or_else(|| DomainError::Internal {
            message: "batch.execute returned no result object".to_string(),
        })?;
        let rows = response
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| DomainError::Internal {
                message: "batch.execute result has no items array".to_string(),
            })?;
        for row in rows {
            let Some(id) = row.get("id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(err) = row.get("error").filter(|v| !v.is_null()) {
                let status = err
                    .get("status")
                    .and_then(Value::as_i64)
                    .and_then(|code| i32::try_from(code).ok());
                let code = err
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("BRIDGE_ERROR")
                    .to_string();
                let message = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("batch item failed")
                    .to_string();
                let target = err
                    .get("target")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                outcomes.insert(
                    id.to_string(),
                    BatchOutcome::Err {
                        status,
                        error: RpcError {
                            code,
                            message,
                            target,
                        },
                    },
                );
            } else {
                let result = row.get("result").cloned().unwrap_or(Value::Null);
                outcomes.insert(id.to_string(), BatchOutcome::Ok(result));
            }
        }
    }
    Ok(outcomes)
}

/// Resolves a function entry from an explicit `entry` or an interior `address`.
pub(super) async fn resolve_target_entry(
    state: &Arc<McpState>,
    md5: &str,
    label: &str,
    entry: Option<&str>,
    address: Option<&str>,
) -> Result<String> {
    let clean_entry = entry.map(str::trim).filter(|value| !value.is_empty());
    let clean_address = address.map(str::trim).filter(|value| !value.is_empty());
    if let Some(explicit) = clean_entry {
        return Ok(explicit.to_string());
    }
    let Some(target) = clean_address else {
        return Err(DomainError::invalid_argument(
            "entry",
            format!("`{label}` requires a non-blank `entry` or `address`"),
        )
        .into());
    };
    let envelope = session::call(
        state,
        md5,
        "address.resolve",
        json!({ "selector": { "address": target } }),
    )
    .await?;
    let resolved = envelope.result.unwrap_or(Value::Null);
    let found = resolved
        .pointer("/function/entry")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            DomainError::missing_target(
                target,
                format!("address `{target}` is not inside a function"),
            )
        })?;
    Ok(found.to_string())
}

/// Collected list pages or per-item bridge failure keyed by batch item ID.
pub(super) type DrainedPages = BTreeMap<String, Result<Vec<Value>, (Option<i32>, RpcError)>>;

/// Pagination state for one active list item in [`drain_list_pages`].
struct CursorState {
    /// Bridge list method name.
    method: &'static str,
    /// Original request arguments without `cursor`.
    base_args: Value,
    /// Collected items across pages.
    items: Vec<Value>,
    /// Next page token when more items exist.
    next_cursor: Option<String>,
    /// Visited cursors for loop detection.
    seen_cursors: HashSet<String>,
}

/// Seeds completed pages and active cursor states from the initial batch outcomes.
fn seed_cursor_states(
    requests: &[BatchItem],
    initial: &BTreeMap<String, BatchOutcome>,
) -> Result<(DrainedPages, BTreeMap<String, CursorState>)> {
    let mut results = BTreeMap::new();
    let mut active = BTreeMap::new();
    for req in requests {
        match initial.get(&req.id) {
            Some(BatchOutcome::Ok(page)) => {
                let page_items = page
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let next_cursor = page
                    .get("next_cursor")
                    .and_then(Value::as_str)
                    .filter(|cursor| !cursor.is_empty())
                    .map(str::to_string);
                if next_cursor.is_none() {
                    results.insert(req.id.clone(), Ok(page_items));
                } else {
                    active.insert(
                        req.id.clone(),
                        CursorState {
                            method: req.method,
                            base_args: req.arguments.clone(),
                            items: page_items,
                            next_cursor,
                            seen_cursors: HashSet::new(),
                        },
                    );
                }
            }
            Some(BatchOutcome::Err { status, error }) => {
                results.insert(req.id.clone(), Err((*status, error.clone())));
            }
            None => {
                return Err(DomainError::Internal {
                    message: format!("batch.execute omitted response for item `{}`", req.id),
                }
                .into());
            }
        }
    }
    Ok((results, active))
}

/// Drains `next_cursor` pages for list items through batched `batch.execute` calls.
pub(super) async fn drain_list_pages(
    state: &Arc<McpState>,
    md5: &str,
    requests: &[BatchItem],
    initial: BTreeMap<String, BatchOutcome>,
) -> Result<DrainedPages> {
    let (mut results, mut active) = seed_cursor_states(requests, &initial)?;

    while !active.is_empty() {
        let mut follow_up = Vec::with_capacity(active.len());
        for (id, cursor_state) in &mut active {
            let Some(cursor) = cursor_state.next_cursor.clone() else {
                continue;
            };
            if !cursor_state.seen_cursors.insert(cursor.clone()) {
                return Err(DomainError::Internal {
                    message: format!("bridge repeated pagination cursor for `{id}`"),
                }
                .into());
            }
            let mut args = cursor_state.base_args.clone();
            if !args.get("page").is_some_and(Value::is_object) {
                args["page"] = json!({ "limit": MAX_PAGE_LIMIT });
            }
            args["page"]["cursor"] = json!(cursor);
            follow_up.push(BatchItem {
                id: id.clone(),
                method: cursor_state.method,
                arguments: args,
            });
        }
        let outcomes = execute_batch(state, md5, &follow_up).await?;
        let mut finished = Vec::new();
        for (id, cursor_state) in &mut active {
            match outcomes.get(id) {
                Some(BatchOutcome::Ok(page)) => {
                    if let Some(items) = page.get("items").and_then(Value::as_array) {
                        cursor_state.items.extend(items.iter().cloned());
                    }
                    cursor_state.next_cursor = page
                        .get("next_cursor")
                        .and_then(Value::as_str)
                        .filter(|cursor| !cursor.is_empty())
                        .map(str::to_string);
                    if cursor_state.next_cursor.is_none() {
                        finished.push(id.clone());
                    }
                }
                Some(BatchOutcome::Err { status, error }) => {
                    results.insert(id.clone(), Err((*status, error.clone())));
                    finished.push(id.clone());
                }
                None => {
                    return Err(DomainError::Internal {
                        message: format!("batch.execute omitted page response for `{id}`"),
                    }
                    .into());
                }
            }
        }
        for id in finished {
            if let Some(done) = active.remove(&id) {
                results.entry(id).or_insert(Ok(done.items));
            }
        }
    }

    Ok(results)
}

/// Parses a `space:hex` or bare hexadecimal address with `default_space`.
pub(super) fn parse_address(raw: &str, default_space: &str) -> Option<ParsedAddress> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (space, hex_part) = match trimmed.find(':') {
        Some(0) => return None,
        Some(colon) => {
            let prefix = trimmed[..colon].trim();
            if prefix.is_empty()
                || matches!(
                    prefix.to_ascii_lowercase().as_str(),
                    "stack" | "register" | "const" | "unique" | "variable" | "hash"
                )
                || !is_valid_space(prefix)
            {
                return None;
            }
            (prefix, trimmed[colon + 1..].trim())
        }
        None => (default_space, trimmed),
    };
    let digits = hex_part
        .strip_prefix("0x")
        .or_else(|| hex_part.strip_prefix("0X"))
        .unwrap_or(hex_part);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let normalized_space = if space.eq_ignore_ascii_case("ram") {
        "ram".to_string()
    } else {
        space.to_string()
    };
    let offset = u64::from_str_radix(digits, 16).ok()?;
    let width = digits.len().max(1);
    Some(ParsedAddress {
        canonical: format!("{normalized_space}:{offset:0width$x}"),
        space: normalized_space,
        offset,
    })
}

/// Normalizes an address or external label into a canonical node identifier.
pub(super) fn canonical_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(parsed) = parse_address(trimmed, "ram") {
        let min_width = if parsed.offset > 0xffff_ffff { 16 } else { 8 };
        let width = min_width.max(trimmed.len().saturating_sub(parsed.space.len() + 1));
        return format!("{}:{:0width$x}", parsed.space, parsed.offset);
    }
    trimmed.to_string()
}

/// Returns `true` when two addresses denote the same space and byte offset.
pub(super) fn same_address(left: &str, right: &str) -> bool {
    match (parse_address(left, "ram"), parse_address(right, "ram")) {
        (Some(a), Some(b)) => a.space == b.space && a.offset == b.offset,
        _ => left.trim() == right.trim(),
    }
}

/// Returns `true` when `space` has valid Ghidra address-space characters.
fn is_valid_space(space: &str) -> bool {
    let mut bytes = space.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests;
