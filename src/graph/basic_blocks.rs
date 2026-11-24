// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Basic-block control-flow graph construction for `ghidra_graph basic_blocks`.

use super::{
    drain_list_pages, execute_batch, parse_address, resolve_target_entry, same_address, BatchItem,
    BatchOutcome, MAX_PAGE_LIMIT,
};
use crate::error::DomainError;
use crate::state::McpState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Default instruction scan timeout in milliseconds.
const DEFAULT_SCAN_TIMEOUT_MS: u64 = 60_000;
/// Maximum instruction scan timeout in milliseconds.
const MAX_SCAN_TIMEOUT_MS: u64 = 300_000;

/// Input parameters of `ghidra_graph basic_blocks`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BasicBlocksParams {
    /// Function entry address.
    entry: Option<String>,
    /// Interior address resolved to its function when `entry` is absent.
    address: Option<String>,
    /// Instruction scan timeout in milliseconds.
    timeout_ms: Option<u64>,
}

/// One instruction summary inside a basic block.
#[derive(Clone, Debug, Serialize)]
struct BlockInstruction {
    /// Instruction address string.
    address: String,
    /// Instruction byte length.
    length: usize,
    /// Mnemonic text.
    mnemonic: String,
    /// Formatted assembly text line.
    text: String,
}

/// One partitioned basic block in a function body.
#[derive(Clone, Debug, Serialize)]
struct BasicBlock {
    /// Block node identifier (`block:0`, `block:1`, and so on).
    id: String,
    /// Start address of the block.
    address: String,
    /// Address of the last instruction in the block.
    end: String,
    /// Number of instructions in the block.
    instruction_count: usize,
    /// Formatted disassembly lines in execution sequence.
    lines: Vec<String>,
    /// Instruction records in execution sequence.
    instructions: Vec<BlockInstruction>,
}

/// One branch target outside the function body range.
#[derive(Clone, Debug, Serialize)]
struct ExternalTarget {
    /// External node identifier (`external:<address>`).
    id: String,
    /// Target address string.
    address: String,
}

/// One directed control-flow edge between basic blocks or external targets.
#[derive(Clone, Debug, Serialize)]
struct FlowEdge {
    /// Source block identifier.
    from: String,
    /// Target block or external identifier.
    to: String,
    /// Reference type or fall-through label.
    label: String,
    /// Edge category (`taken`, `fallthrough`, or `flow`).
    kind: &'static str,
}

/// Output of block leader and branch target analysis.
struct Partition {
    /// Sorted start instruction indexes of all basic blocks.
    starts: Vec<usize>,
    /// Target `(target_address, label)` pairs per instruction index.
    targets: Vec<Vec<(String, String)>>,
    /// Jump or branch instructions without resolved jump references.
    unresolved: usize,
}

/// Returns the JSON Schema of `params` for `ghidra_graph basic_blocks`.
pub(crate) fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "entry": {
                "type": "string",
                "minLength": 1,
                "description": "The function entry address. Provide entry or address."
            },
            "address": {
                "type": "string",
                "minLength": 1,
                "description": "An address inside the function when entry is absent."
            },
            "timeout_ms": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_SCAN_TIMEOUT_MS,
                "default": DEFAULT_SCAN_TIMEOUT_MS,
                "description": "The instruction scan time limit in milliseconds."
            }
        },
        "additionalProperties": false
    })
}

/// Runs `ghidra_graph basic_blocks` with batched function, instruction, and reference reads.
pub(crate) async fn run_basic_blocks(
    state: &Arc<McpState>,
    md5: &str,
    label: &str,
    params: BasicBlocksParams,
) -> Result<(String, Value)> {
    let timeout_ms = params.timeout_ms.unwrap_or(DEFAULT_SCAN_TIMEOUT_MS);
    if !(1..=MAX_SCAN_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(DomainError::invalid_argument(
            "timeout_ms",
            format!("`{label}` requires `timeout_ms` in 1..={MAX_SCAN_TIMEOUT_MS}"),
        )
        .into());
    }
    let initial_entry = resolve_target_entry(
        state,
        md5,
        label,
        params.entry.as_deref(),
        params.address.as_deref(),
    )
    .await?;

    let mut outcomes = fetch_initial_bundle(state, md5, &initial_entry, timeout_ms).await?;
    let (fn_val, entry, fn_name, fn_summary) =
        unpack_function_meta(outcomes.remove("fn"), &initial_entry)?;

    let bounds = fn_val.get("body").and_then(Value::as_object);
    let body_start = bounds
        .and_then(|b| b.get("start"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let body_end = bounds
        .and_then(|b| b.get("end"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let (Some(start), Some(end)) = (body_start, body_end) else {
        return Ok(empty_blocks_result(
            &entry,
            &fn_name,
            &fn_summary,
            "This function has no instruction body.",
            "External functions do not have a local control-flow graph.",
        ));
    };

    let raw_instructions = collect_body_instructions(
        state,
        md5,
        &initial_entry,
        start,
        end,
        timeout_ms,
        outcomes.remove("ins"),
    )
    .await?;
    let instructions =
        filter_body_instructions(state, md5, &entry, bounds, start, end, raw_instructions).await?;
    if instructions.is_empty() {
        return Ok(empty_blocks_result(
            &entry,
            &fn_name,
            &fn_summary,
            "No instructions in this body.",
            "Ghidra reported no instruction flow.",
        ));
    }

    let references = collect_body_references(
        state,
        md5,
        &initial_entry,
        start,
        end,
        outcomes.remove("ref"),
    )
    .await?;
    let partitioned = partition_blocks(&instructions, &references);
    let (blocks, external_targets, edges) =
        build_graph_elements(&instructions, &partitioned.starts, &partitioned.targets);
    let scope = if partitioned.unresolved > 0 {
        format!("{} unresolved jumps", partitioned.unresolved)
    } else {
        String::new()
    };
    let summary = format!(
        "Built {} basic block(s) and {} edge(s) for {}",
        blocks.len(),
        edges.len(),
        fn_name
    );
    let payload = json!({
        "entry": entry,
        "function": fn_summary,
        "has_body": true,
        "empty_reason": Value::Null,
        "scope": scope,
        "unresolved_jumps": partitioned.unresolved,
        "blocks": blocks,
        "external_targets": external_targets,
        "edges": edges,
    });
    Ok((summary, payload))
}

/// Sends the initial three-item `batch.execute` request for `function.get`,
/// `instruction.list`, and `reference.list`.
async fn fetch_initial_bundle(
    state: &Arc<McpState>,
    md5: &str,
    initial_entry: &str,
    timeout_ms: u64,
) -> Result<BTreeMap<String, BatchOutcome>> {
    let initial_requests = vec![
        BatchItem {
            id: "fn".to_string(),
            method: "function.get",
            arguments: json!({
                "selector": { "entry": initial_entry },
                "projection": {
                    "fields": ["entry", "name", "namespace", "demangled_name", "body"],
                },
            }),
        },
        BatchItem {
            id: "ins".to_string(),
            method: "instruction.list",
            arguments: json!({
                "scan": {
                    "range": { "start": initial_entry },
                    "timeout_ms": timeout_ms,
                },
                "page": { "limit": MAX_PAGE_LIMIT },
            }),
        },
        BatchItem {
            id: "ref".to_string(),
            method: "reference.list",
            arguments: json!({
                "filter": { "direction": "from", "entry": initial_entry },
                "page": { "limit": MAX_PAGE_LIMIT },
            }),
        },
    ];
    execute_batch(state, md5, &initial_requests).await
}

/// Extracts the `function.get` payload and formatted summary from the initial batch.
fn unpack_function_meta(
    outcome: Option<BatchOutcome>,
    initial_entry: &str,
) -> Result<(Value, String, String, Value)> {
    let fn_val = match outcome {
        Some(BatchOutcome::Ok(val)) => val,
        Some(BatchOutcome::Err { status, error }) => {
            return Err(DomainError::from_bridge(status, &error).into());
        }
        None => {
            return Err(DomainError::Internal {
                message: "batch.execute omitted function.get response".to_string(),
            }
            .into());
        }
    };
    let entry = non_empty_str(&fn_val, "entry")
        .unwrap_or(initial_entry)
        .to_string();
    let fn_name = non_empty_str(&fn_val, "name").unwrap_or(&entry).to_string();
    let fn_summary = json!({
        "entry": entry,
        "name": fn_name,
        "namespace": non_empty_str(&fn_val, "namespace"),
        "demangled_name": non_empty_str(&fn_val, "demangled_name"),
        "body": fn_val.get("body").cloned().unwrap_or(Value::Null),
    });
    Ok((fn_val, entry, fn_name, fn_summary))
}

/// Builds an empty `basic_blocks` response when a function has no body or instructions.
fn empty_blocks_result(
    entry: &str,
    fn_name: &str,
    fn_summary: &Value,
    empty_reason: &str,
    scope: &str,
) -> (String, Value) {
    (
        format!("No basic blocks for {fn_name}: {empty_reason}"),
        json!({
            "entry": entry,
            "function": fn_summary,
            "has_body": false,
            "empty_reason": empty_reason,
            "scope": scope,
            "unresolved_jumps": 0,
            "blocks": [],
            "external_targets": [],
            "edges": [],
        }),
    )
}

/// Reuses the batched instruction page when it covers `start..=end`, or fetches the exact range.
async fn collect_body_instructions(
    state: &Arc<McpState>,
    md5: &str,
    initial_entry: &str,
    start: &str,
    end: &str,
    timeout_ms: u64,
    initial_outcome: Option<BatchOutcome>,
) -> Result<Vec<Value>> {
    let start_parsed = parse_address(start, "ram");
    let end_parsed = parse_address(end, "ram");

    if same_address(initial_entry, start) {
        if let Some(BatchOutcome::Ok(page)) = initial_outcome {
            let scan_complete =
                page.pointer("/scan/complete").and_then(Value::as_bool) != Some(false);
            let page_items = page
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let next_cursor = page
                .get("next_cursor")
                .and_then(Value::as_str)
                .filter(|cursor| !cursor.is_empty());
            let covered_end = match (&end_parsed, page_items.last()) {
                (Some(end_addr), Some(last)) => last
                    .get("address")
                    .and_then(Value::as_str)
                    .and_then(|addr| parse_address(addr, "ram"))
                    .is_some_and(|last_addr| {
                        last_addr.space != end_addr.space || last_addr.offset >= end_addr.offset
                    }),
                _ => false,
            };
            if (next_cursor.is_none() && scan_complete) || covered_end {
                return Ok(trim_instructions_to_bounds(
                    page_items,
                    start_parsed.as_ref(),
                    end_parsed.as_ref(),
                ));
            }
        }
    }

    let req = BatchItem {
        id: "ins_range".to_string(),
        method: "instruction.list",
        arguments: json!({
            "scan": {
                "range": { "start": start, "end": end },
                "timeout_ms": timeout_ms,
            },
            "page": { "limit": MAX_PAGE_LIMIT },
        }),
    };
    let outcomes = execute_batch(state, md5, std::slice::from_ref(&req)).await?;
    let mut pages = drain_list_pages(state, md5, std::slice::from_ref(&req), outcomes).await?;
    match pages.remove("ins_range") {
        Some(Ok(items)) => Ok(items),
        Some(Err((status, err))) => Err(DomainError::from_bridge(status, &err).into()),
        None => Ok(Vec::new()),
    }
}

/// Retains instructions whose parsed addresses lie within `start..=end`.
fn trim_instructions_to_bounds(
    items: Vec<Value>,
    start: Option<&super::ParsedAddress>,
    end: Option<&super::ParsedAddress>,
) -> Vec<Value> {
    let (Some(start_addr), Some(end_addr)) = (start, end) else {
        return items;
    };
    items
        .into_iter()
        .filter(|instr| {
            let Some(addr) = instr
                .get("address")
                .and_then(Value::as_str)
                .and_then(|raw| parse_address(raw, "ram"))
            else {
                return true;
            };
            addr.space == start_addr.space
                && addr.offset >= start_addr.offset
                && (addr.space != end_addr.space || addr.offset <= end_addr.offset)
        })
        .collect()
}

/// Drains `reference.list` pages from the initial batch or falls back to `from_range`.
async fn collect_body_references(
    state: &Arc<McpState>,
    md5: &str,
    initial_entry: &str,
    start: &str,
    end: &str,
    initial_outcome: Option<BatchOutcome>,
) -> Result<Vec<Value>> {
    if let Some(outcome) = initial_outcome {
        if matches!(outcome, BatchOutcome::Ok(_)) {
            let req = BatchItem {
                id: "ref".to_string(),
                method: "reference.list",
                arguments: json!({
                    "filter": { "direction": "from", "entry": initial_entry },
                    "page": { "limit": MAX_PAGE_LIMIT },
                }),
            };
            let initial_map = BTreeMap::from([("ref".to_string(), outcome)]);
            let mut pages =
                drain_list_pages(state, md5, std::slice::from_ref(&req), initial_map).await?;
            if let Some(Ok(items)) = pages.remove("ref") {
                return Ok(items);
            }
        }
    }

    let range_req = BatchItem {
        id: "ref_range".to_string(),
        method: "reference.list",
        arguments: json!({
            "filter": {
                "direction": "from",
                "from_range": { "start": start, "end": end },
            },
            "page": { "limit": MAX_PAGE_LIMIT },
        }),
    };
    let outcomes = execute_batch(state, md5, std::slice::from_ref(&range_req)).await?;
    let mut pages =
        drain_list_pages(state, md5, std::slice::from_ref(&range_req), outcomes).await?;
    match pages.remove("ref_range") {
        Some(Ok(items)) => Ok(items),
        Some(Err((status, err))) => Err(DomainError::from_bridge(status, &err).into()),
        None => Ok(Vec::new()),
    }
}

/// Filters out interleaved instructions from other functions when the body has disjoint ranges.
async fn filter_body_instructions(
    state: &Arc<McpState>,
    md5: &str,
    entry: &str,
    bounds: Option<&serde_json::Map<String, Value>>,
    start: &str,
    end: &str,
    mut instructions: Vec<Value>,
) -> Result<Vec<Value>> {
    let Some(body_start) = parse_address(start, "ram") else {
        return Ok(instructions);
    };
    let Some(body_end) = parse_address(end, "ram") else {
        return Ok(instructions);
    };
    let Some(num_addresses) = bounds
        .and_then(|b| b.get("num_addresses"))
        .and_then(Value::as_u64)
    else {
        return Ok(instructions);
    };
    if body_end.offset < body_start.offset {
        return Ok(instructions);
    }
    let span = u128::from(body_end.offset) - u128::from(body_start.offset) + 1;
    if u128::from(num_addresses) == span || instructions.is_empty() {
        return Ok(instructions);
    }

    let requests: Vec<BatchItem> = instructions
        .iter()
        .enumerate()
        .map(|(idx, instr)| BatchItem {
            id: format!("resolve:{idx}"),
            method: "address.resolve",
            arguments: json!({
                "selector": {
                    "address": instr.get("address").and_then(Value::as_str).unwrap_or(""),
                }
            }),
        })
        .collect();
    let outcomes = execute_batch(state, md5, &requests).await?;
    let mut filtered = Vec::with_capacity(instructions.len());
    for (idx, instr) in instructions.drain(..).enumerate() {
        let owns = match outcomes.get(&format!("resolve:{idx}")) {
            Some(BatchOutcome::Ok(val)) => val
                .pointer("/function/entry")
                .and_then(Value::as_str)
                .is_some_and(|owner| same_address(owner, entry)),
            _ => false,
        };
        if owns {
            filtered.push(instr);
        }
    }
    Ok(filtered)
}

/// Map from source address string to `(target_address, reference_type)` pairs.
type JumpRefMap = HashMap<String, Vec<(String, String)>>;

/// Indexes jump and branch references by exact and canonical source address.
fn index_jump_references(references: &[Value]) -> (JumpRefMap, JumpRefMap) {
    let mut refs_by_exact: JumpRefMap = HashMap::new();
    let mut refs_by_canon: JumpRefMap = HashMap::new();
    for ref_item in references {
        let ref_type = ref_item.get("type").and_then(Value::as_str).unwrap_or("");
        let upper_type = ref_type.to_ascii_uppercase();
        if !(upper_type.contains("JUMP") || upper_type.contains("BRANCH")) {
            continue;
        }
        let Some(from) = non_empty_str(ref_item, "from") else {
            continue;
        };
        let to = ref_item
            .get("to")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let pair = (to, ref_type.to_string());
        refs_by_exact
            .entry(from.to_string())
            .or_default()
            .push(pair.clone());
        if let Some(parsed) = parse_address(from, "ram") {
            refs_by_canon
                .entry(parsed.canonical)
                .or_default()
                .push(pair);
        }
    }
    (refs_by_exact, refs_by_canon)
}

/// Indexes jump and branch references by source address and computes block leaders.
fn partition_blocks(instructions: &[Value], references: &[Value]) -> Partition {
    let mut exact_index = HashMap::with_capacity(instructions.len());
    let mut canon_index = HashMap::with_capacity(instructions.len());
    for (idx, instr) in instructions.iter().enumerate() {
        let addr = instr.get("address").and_then(Value::as_str).unwrap_or("");
        exact_index.entry(addr.to_string()).or_insert(idx);
        if let Some(parsed) = parse_address(addr, "ram") {
            canon_index.entry(parsed.canonical).or_insert(idx);
        }
    }

    let (refs_by_exact, refs_by_canon) = index_jump_references(references);

    let mut targets = vec![Vec::new(); instructions.len()];
    let mut leaders = BTreeSet::from([0usize]);
    let mut unresolved = 0usize;

    for (idx, instr) in instructions.iter().enumerate() {
        let addr = instr.get("address").and_then(Value::as_str).unwrap_or("");
        let flow = instr
            .get("flow_type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase();
        let mut branch_targets: Vec<(String, String)> = Vec::new();
        if flow.contains("JUMP") || flow.contains("BRANCH") {
            let found = refs_by_exact.get(addr).or_else(|| {
                parse_address(addr, "ram").and_then(|parsed| refs_by_canon.get(&parsed.canonical))
            });
            if let Some(list) = found {
                for (to, kind) in list {
                    if !branch_targets
                        .iter()
                        .any(|(prev_to, prev_k)| prev_to == to && prev_k == kind)
                    {
                        branch_targets.push((to.clone(), kind.clone()));
                    }
                }
            }
            if branch_targets.is_empty() {
                unresolved += 1;
            }
        }
        let fall_through = instr
            .get("fall_through")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !fall_through.is_empty() {
            let edge_label = if flow.contains("CONDITIONAL") {
                "Fall through"
            } else {
                ""
            };
            branch_targets.push((fall_through.to_string(), edge_label.to_string()));
        }

        let breaks_flow = flow.contains("JUMP")
            || flow.contains("BRANCH")
            || flow.contains("TERMINATOR")
            || flow.contains("RETURN")
            || fall_through.is_empty();
        if breaks_flow {
            if idx + 1 < instructions.len() {
                leaders.insert(idx + 1);
            }
            for (to, _) in &branch_targets {
                if let Some(pos) = lookup_instruction(&exact_index, &canon_index, to) {
                    leaders.insert(pos);
                }
            }
        } else if idx + 1 < instructions.len() {
            let next_addr = instructions[idx + 1]
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !same_address(fall_through, next_addr) {
                leaders.insert(idx + 1);
                if let Some(pos) = lookup_instruction(&exact_index, &canon_index, fall_through) {
                    leaders.insert(pos);
                }
            }
        }
        targets[idx] = branch_targets;
    }

    Partition {
        starts: leaders.into_iter().collect(),
        targets,
        unresolved,
    }
}

/// Builds basic blocks, external targets, and typed edges from partitioned slices.
fn build_graph_elements(
    instructions: &[Value],
    starts: &[usize],
    targets: &[Vec<(String, String)>],
) -> (Vec<BasicBlock>, Vec<ExternalTarget>, Vec<FlowEdge>) {
    let mut slices: Vec<(usize, &[Value])> = Vec::with_capacity(starts.len());
    let mut exact_owner: HashMap<String, String> = HashMap::new();
    let mut canon_owner: HashMap<String, String> = HashMap::new();

    for (block_idx, &start_idx) in starts.iter().enumerate() {
        let end_idx = starts
            .get(block_idx + 1)
            .copied()
            .unwrap_or(instructions.len());
        let slice = &instructions[start_idx..end_idx];
        let block_id = format!("block:{block_idx}");
        for instr in slice {
            let addr = instr.get("address").and_then(Value::as_str).unwrap_or("");
            exact_owner
                .entry(addr.to_string())
                .or_insert_with(|| block_id.clone());
            if let Some(parsed) = parse_address(addr, "ram") {
                canon_owner
                    .entry(parsed.canonical)
                    .or_insert_with(|| block_id.clone());
            }
        }
        slices.push((end_idx - 1, slice));
    }

    let blocks: Vec<BasicBlock> = slices
        .iter()
        .enumerate()
        .map(|(block_idx, (_, slice))| {
            let first_addr = slice[0]
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let last_addr = slice[slice.len() - 1]
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let block_instructions: Vec<BlockInstruction> =
                slice.iter().map(format_instruction).collect();
            let lines = block_instructions
                .iter()
                .map(|item| item.text.clone())
                .collect();
            BasicBlock {
                id: format!("block:{block_idx}"),
                address: first_addr,
                end: last_addr,
                instruction_count: block_instructions.len(),
                lines,
                instructions: block_instructions,
            }
        })
        .collect();

    let mut raw_edges: Vec<(String, String, String)> = Vec::new();
    let mut external_seen = HashSet::new();
    let mut external_targets = Vec::new();

    for (block_idx, (last_idx, _)) in slices.iter().enumerate() {
        let from_id = format!("block:{block_idx}");
        for (to_addr, edge_label) in &targets[*last_idx] {
            let to_id = exact_owner
                .get(to_addr)
                .cloned()
                .or_else(|| {
                    parse_address(to_addr, "ram")
                        .and_then(|parsed| canon_owner.get(&parsed.canonical).cloned())
                })
                .unwrap_or_else(|| {
                    let ext_id = format!("external:{to_addr}");
                    if external_seen.insert(ext_id.clone()) {
                        external_targets.push(ExternalTarget {
                            id: ext_id.clone(),
                            address: to_addr.clone(),
                        });
                    }
                    ext_id
                });
            raw_edges.push((from_id.clone(), to_id, edge_label.clone()));
        }
    }

    let edges = classify_flow_edges(raw_edges);
    (blocks, external_targets, edges)
}

/// Assigns `taken`, `fallthrough`, or `flow` categories to raw control-flow edges.
fn classify_flow_edges(raw_edges: Vec<(String, String, String)>) -> Vec<FlowEdge> {
    let conditional_sources: HashSet<String> = raw_edges
        .iter()
        .filter(|(_, _, edge_label)| is_conditional_label(edge_label))
        .map(|(from, _, _)| from.clone())
        .collect();

    raw_edges
        .into_iter()
        .map(|(from, to, edge_label)| {
            let kind = if is_conditional_label(&edge_label) {
                "taken"
            } else if (edge_label.eq_ignore_ascii_case("fall through")
                || edge_label.eq_ignore_ascii_case("fall-through"))
                && conditional_sources.contains(&from)
            {
                "fallthrough"
            } else {
                "flow"
            };
            FlowEdge {
                from,
                to,
                label: edge_label,
                kind,
            }
        })
        .collect()
}

/// Formats one instruction value into a [`BlockInstruction`].
fn format_instruction(instr: &Value) -> BlockInstruction {
    let address = instr
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mnemonic = instr
        .get("mnemonic")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let operands = instr
        .get("operands")
        .and_then(Value::as_array)
        .map(|ops| {
            ops.iter()
                .filter_map(|op| match op {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let text = format!("{mnemonic} {operands}").trim().to_string();
    BlockInstruction {
        address,
        length: instruction_byte_length(instr),
        mnemonic,
        text,
    }
}

/// Returns the byte length of one instruction record, with fallback `1`.
fn instruction_byte_length(instr: &Value) -> usize {
    if let Some(len) = instr
        .get("length")
        .and_then(Value::as_u64)
        .filter(|&count| count > 0)
    {
        return usize::try_from(len).unwrap_or(usize::MAX);
    }
    if let Some(bytes) = instr.get("bytes").and_then(Value::as_object) {
        let encoding = bytes.get("encoding").and_then(Value::as_str).unwrap_or("");
        let data = bytes.get("data").and_then(Value::as_str).unwrap_or("");
        let count = if encoding == "base64" {
            base64_byte_len(data)
        } else {
            let hex_digits = data.chars().filter(|ch| !ch.is_whitespace()).count();
            hex_digits.div_ceil(2)
        };
        if count > 0 {
            return count;
        }
    }
    1
}

/// Returns the decoded byte length of a base64 string.
fn base64_byte_len(data: &str) -> usize {
    let clean: Vec<u8> = data
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if clean.len() < 4 {
        return 0;
    }
    let padding = clean
        .iter()
        .rev()
        .take(2)
        .take_while(|&&byte| byte == b'=')
        .count();
    (clean.len() * 3) / 4 - padding
}

/// Returns `true` when `label` names a conditional jump or branch.
fn is_conditional_label(label: &str) -> bool {
    let upper = label.to_ascii_uppercase();
    upper.contains("CONDITIONAL") && !upper.contains("UNCONDITIONAL")
}

/// Finds an instruction index by exact address or canonical `space:offset`.
fn lookup_instruction(
    exact_map: &HashMap<String, usize>,
    canon_map: &HashMap<String, usize>,
    addr: &str,
) -> Option<usize> {
    if let Some(&idx) = exact_map.get(addr) {
        return Some(idx);
    }
    parse_address(addr, "ram").and_then(|parsed| canon_map.get(&parsed.canonical).copied())
}

/// Returns a trimmed non-empty string field from `obj`.
fn non_empty_str<'a>(obj: &'a Value, field: &str) -> Option<&'a str> {
    obj.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
