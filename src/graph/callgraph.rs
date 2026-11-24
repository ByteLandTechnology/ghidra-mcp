// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Bounded level-by-level BFS call-graph construction for `ghidra_graph callgraph`.

use super::{
    canonical_id, drain_list_pages, execute_batch, resolve_target_entry, BatchItem, MAX_PAGE_LIMIT,
};
use crate::error::DomainError;
use crate::session;
use crate::state::McpState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Default maximum hop depth per direction.
const DEFAULT_MAX_DEPTH: usize = 2;
/// Hard upper limit on hop depth per direction, also applied in interactive expansion mode.
const MAX_ALLOWED_DEPTH: usize = 10;
/// Default maximum number of nodes in one call graph.
const DEFAULT_MAX_NODES: usize = 80;
/// Hard upper limit on nodes in one call graph.
const MAX_ALLOWED_NODES: usize = 1000;
/// Default maximum number of directed call edges in one call graph.
const DEFAULT_MAX_EDGES: usize = 240;
/// Hard upper limit on directed call edges in one call graph.
const MAX_ALLOWED_EDGES: usize = 5000;

/// Direction mode for `ghidra_graph callgraph`.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DirectionParam {
    /// Traverse callers and callees.
    #[default]
    Both,
    /// Traverse callers only.
    Callers,
    /// Traverse callees only.
    Callees,
}

/// Active traversal arm for one queued node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// Functions that call the node.
    Callers,
    /// Functions that the node calls.
    Callees,
}

impl Arm {
    /// Returns the `function_call.list` filter value.
    fn as_str(self) -> &'static str {
        match self {
            Self::Callers => "callers",
            Self::Callees => "callees",
        }
    }
}

/// Explicit sets of expanded entries for interactive call-graph exploration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExpansionParam {
    /// Entries whose caller branches are expanded.
    #[serde(default)]
    callers: Vec<String>,
    /// Entries whose callee branches are expanded.
    #[serde(default)]
    callees: Vec<String>,
}

/// Input parameters of `ghidra_graph callgraph`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallGraphParams {
    /// Root function entry address.
    entry: Option<String>,
    /// Interior address resolved to its function when `entry` is absent.
    address: Option<String>,
    /// Traversal direction when `expansion` is absent.
    #[serde(default)]
    direction: DirectionParam,
    /// Maximum hop depth in each active direction.
    max_depth: Option<usize>,
    /// Optional override for caller hop depth.
    callers_depth: Option<usize>,
    /// Optional override for callee hop depth.
    callees_depth: Option<usize>,
    /// Maximum node count in the response.
    max_nodes: Option<usize>,
    /// Maximum edge count in the response.
    max_edges: Option<usize>,
    /// Interactive branch expansion sets.
    expansion: Option<ExpansionParam>,
}

/// Expansion state and unique neighbor count of one branch on a node.
#[derive(Clone, Debug, Default, Serialize)]
struct BranchState {
    /// True when the branch was expanded in this query.
    expanded: bool,
    /// Unique neighbor count discovered on this branch when expanded.
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
}

/// Caller and callee branch states on one node in interactive expansion mode.
#[derive(Clone, Debug, Default, Serialize)]
struct NodeBranches {
    /// Caller branch state.
    #[serde(skip_serializing_if = "Option::is_none")]
    callers: Option<BranchState>,
    /// Callee branch state.
    #[serde(skip_serializing_if = "Option::is_none")]
    callees: Option<BranchState>,
}

/// One function vertex in the call graph.
#[derive(Clone, Debug, Serialize)]
struct GraphNode {
    /// Canonical node identifier (`space:offset`).
    id: String,
    /// Function entry address string from the bridge.
    entry: String,
    /// Primary function symbol name.
    name: String,
    /// Optional function namespace path.
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    /// Optional demangled C++ function name.
    #[serde(skip_serializing_if = "Option::is_none")]
    demangled_name: Option<String>,
    /// Shortest caller hop distance from the root node.
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_distance: Option<usize>,
    /// Shortest callee hop distance from the root node.
    #[serde(skip_serializing_if = "Option::is_none")]
    callee_distance: Option<usize>,
    /// Interactive branch metadata when `expansion` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    branches: Option<NodeBranches>,
}

/// One directed caller-to-callee edge with deduplicated call-site addresses.
#[derive(Clone, Debug, Serialize)]
struct GraphEdge {
    /// Canonical identifier of the caller node.
    from: String,
    /// Canonical identifier of the callee node.
    to: String,
    /// Distinct call-site addresses in `from` that target `to`.
    sites: Vec<String>,
}

/// One frontier query scheduled for the current BFS hop.
#[derive(Clone, Debug)]
struct FrontierItem {
    /// Canonical identifier of the source node.
    source_id: String,
    /// Bridge entry address of the source node.
    source_entry: String,
    /// Display name of the source node for diagnostics.
    source_name: String,
    /// Traversal arm to query.
    arm: Arm,
    /// Hop distance of neighbors discovered from this item.
    distance: usize,
    /// Maximum hop depth permitted on this arm.
    depth_limit: usize,
}

/// Mutable graph accumulator across BFS hops.
struct Builder {
    /// Function nodes with the root node at index `0`.
    nodes: Vec<GraphNode>,
    /// Map from canonical node ID to index in `nodes`.
    node_index: HashMap<String, usize>,
    /// Directed call edges.
    edges: Vec<GraphEdge>,
    /// Map from `(from_id, to_id)` to index in `edges`.
    edge_index: HashMap<(String, String), usize>,
    /// Canonical IDs already queued on the caller arm.
    seen_callers: HashSet<String>,
    /// Canonical IDs already queued on the callee arm.
    seen_callees: HashSet<String>,
    /// Node count cap.
    max_nodes: usize,
    /// Edge count cap.
    max_edges: usize,
    /// True when any cap truncated the graph.
    limited: bool,
    /// True when explicit `expansion` sets control traversal.
    interactive: bool,
}

/// Returns the JSON Schema of `params` for `ghidra_graph callgraph`.
pub(crate) fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "entry": {
                "type": "string",
                "minLength": 1,
                "description": "The root function entry address. Provide entry or address."
            },
            "address": {
                "type": "string",
                "minLength": 1,
                "description": "An address inside the root function when entry is absent."
            },
            "direction": {
                "type": "string",
                "enum": ["both", "callers", "callees"],
                "default": "both",
                "description": "The call direction to traverse from the root function."
            },
            "max_depth": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_ALLOWED_DEPTH,
                "default": DEFAULT_MAX_DEPTH,
                "description": "The maximum hop depth in each active direction."
            },
            "callers_depth": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_ALLOWED_DEPTH,
                "description": "The maximum caller hop depth. Overrides max_depth for callers."
            },
            "callees_depth": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_ALLOWED_DEPTH,
                "description": "The maximum callee hop depth. Overrides max_depth for callees."
            },
            "max_nodes": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_ALLOWED_NODES,
                "default": DEFAULT_MAX_NODES,
                "description": "The maximum number of function nodes in the graph."
            },
            "max_edges": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_ALLOWED_EDGES,
                "default": DEFAULT_MAX_EDGES,
                "description": "The maximum number of directed call edges in the graph."
            },
            "expansion": {
                "type": "object",
                "description": "Explicit entry sets for interactive branch expansion.",
                "properties": {
                    "callers": {
                        "type": "array",
                        "items": { "type": "string", "minLength": 1 }
                    },
                    "callees": {
                        "type": "array",
                        "items": { "type": "string", "minLength": 1 }
                    }
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    })
}

/// Validates integer bounds in [`CallGraphParams`].
fn validate_limits(label: &str, params: &CallGraphParams) -> Result<(usize, usize, usize, usize)> {
    let base_depth = params.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
    if base_depth > MAX_ALLOWED_DEPTH {
        return Err(DomainError::invalid_argument(
            "max_depth",
            format!("`{label}` requires `max_depth` in 0..={MAX_ALLOWED_DEPTH}"),
        )
        .into());
    }
    for (field, val) in [
        ("callers_depth", params.callers_depth),
        ("callees_depth", params.callees_depth),
    ] {
        if let Some(depth) = val {
            if depth > MAX_ALLOWED_DEPTH {
                return Err(DomainError::invalid_argument(
                    field,
                    format!("`{label}` requires `{field}` in 0..={MAX_ALLOWED_DEPTH}"),
                )
                .into());
            }
        }
    }
    let max_nodes = params.max_nodes.unwrap_or(DEFAULT_MAX_NODES);
    if !(1..=MAX_ALLOWED_NODES).contains(&max_nodes) {
        return Err(DomainError::invalid_argument(
            "max_nodes",
            format!("`{label}` requires `max_nodes` in 1..={MAX_ALLOWED_NODES}"),
        )
        .into());
    }
    let max_edges = params.max_edges.unwrap_or(DEFAULT_MAX_EDGES);
    if !(1..=MAX_ALLOWED_EDGES).contains(&max_edges) {
        return Err(DomainError::invalid_argument(
            "max_edges",
            format!("`{label}` requires `max_edges` in 1..={MAX_ALLOWED_EDGES}"),
        )
        .into());
    }
    let inbound_depth = match params.direction {
        DirectionParam::Callees => 0,
        DirectionParam::Both | DirectionParam::Callers => {
            params.callers_depth.unwrap_or(base_depth)
        }
    };
    let outbound_depth = match params.direction {
        DirectionParam::Callers => 0,
        DirectionParam::Both | DirectionParam::Callees => {
            params.callees_depth.unwrap_or(base_depth)
        }
    };
    Ok((inbound_depth, outbound_depth, max_nodes, max_edges))
}

/// Runs `ghidra_graph callgraph` with one batched `function_call.list` wave per BFS hop.
pub(crate) async fn run_callgraph(
    state: &Arc<McpState>,
    md5: &str,
    label: &str,
    params: CallGraphParams,
) -> Result<(String, Value)> {
    let (inbound_depth, outbound_depth, max_nodes, max_edges) = validate_limits(label, &params)?;
    let initial_entry = resolve_target_entry(
        state,
        md5,
        label,
        params.entry.as_deref(),
        params.address.as_deref(),
    )
    .await?;
    let root_envelope = session::call(
        state,
        md5,
        "function.get",
        json!({
            "selector": { "entry": initial_entry },
            "projection": {
                "fields": ["entry", "name", "namespace", "demangled_name"],
            },
        }),
    )
    .await?;
    let root_fn = root_envelope.result.unwrap_or(Value::Null);
    let root_entry = non_empty_str(&root_fn, "entry")
        .unwrap_or(&initial_entry)
        .to_string();
    let root_name = non_empty_str(&root_fn, "name")
        .unwrap_or(&root_entry)
        .to_string();
    let root_namespace = non_empty_str(&root_fn, "namespace").map(str::to_string);
    let root_demangled = non_empty_str(&root_fn, "demangled_name").map(str::to_string);
    let root_id = canonical_id(&root_entry);

    let expanded_sets = params.expansion.map(|exp| {
        let inbound_set: HashSet<String> = exp.callers.iter().map(|e| canonical_id(e)).collect();
        let outbound_set: HashSet<String> = exp.callees.iter().map(|e| canonical_id(e)).collect();
        (inbound_set, outbound_set)
    });

    let frontier = initial_frontier(
        &root_id,
        &root_entry,
        &root_name,
        inbound_depth,
        outbound_depth,
        expanded_sets.is_some(),
    );

    let mut builder = Builder {
        nodes: vec![GraphNode {
            id: root_id.clone(),
            entry: root_entry.clone(),
            name: root_name.clone(),
            namespace: root_namespace.clone(),
            demangled_name: root_demangled.clone(),
            caller_distance: None,
            callee_distance: None,
            branches: None,
        }],
        node_index: HashMap::from([(root_id.clone(), 0)]),
        edges: Vec::new(),
        edge_index: HashMap::new(),
        seen_callers: HashSet::from([root_id.clone()]),
        seen_callees: HashSet::from([root_id.clone()]),
        max_nodes,
        max_edges,
        limited: false,
        interactive: expanded_sets.is_some(),
    };

    let (hops, warnings) = run_bfs_hops(
        state,
        md5,
        &root_id,
        expanded_sets.as_ref(),
        frontier,
        &mut builder,
    )
    .await?;

    let summary = format!(
        "Built call graph for {} ({} node(s), {} edge(s), {} hop(s))",
        root_name,
        builder.nodes.len(),
        builder.edges.len(),
        hops
    );
    let payload = json!({
        "root": root_id,
        "entry": root_entry,
        "function": {
            "entry": root_entry,
            "name": root_name,
            "namespace": root_namespace,
            "demangled_name": root_demangled,
        },
        "nodes": builder.nodes,
        "edges": builder.edges,
        "hops": hops,
        "limited": builder.limited,
        "warnings": warnings,
    });
    Ok((summary, payload))
}

/// Executes level-by-level batched `function_call.list` hops from `frontier`.
async fn run_bfs_hops(
    state: &Arc<McpState>,
    md5: &str,
    root_id: &str,
    expanded_sets: Option<&(HashSet<String>, HashSet<String>)>,
    mut frontier: Vec<FrontierItem>,
    builder: &mut Builder,
) -> Result<(usize, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut hops = 0usize;

    while !frontier.is_empty() {
        let mut active_items = Vec::with_capacity(frontier.len());
        for item in frontier {
            if let Some(sets) = expanded_sets {
                if !builder.mark_branch_state(sets, &item) {
                    continue;
                }
            }
            active_items.push(item);
        }
        if active_items.is_empty() {
            break;
        }
        if builder.edges.len() >= builder.max_edges {
            builder.limited = true;
            break;
        }

        hops += 1;
        let requests: Vec<BatchItem> = active_items
            .iter()
            .enumerate()
            .map(|(idx, item)| BatchItem {
                id: format!("hop:{hops}:{idx}"),
                method: "function_call.list",
                arguments: json!({
                    "filter": {
                        "entry": item.source_entry,
                        "direction": item.arm.as_str(),
                    },
                    "page": { "limit": MAX_PAGE_LIMIT },
                }),
            })
            .collect();

        let initial_outcomes = execute_batch(state, md5, &requests).await?;
        let pages = drain_list_pages(state, md5, &requests, initial_outcomes).await?;

        let mut next_frontier = Vec::new();
        for (item, req) in active_items.iter().zip(requests.iter()) {
            let records = match pages.get(&req.id) {
                Some(Ok(items)) => items.clone(),
                Some(Err((status, err))) => {
                    if item.source_id == root_id {
                        return Err(DomainError::from_bridge(*status, err).into());
                    }
                    warnings.push(format!(
                        "Could not expand {}: {}",
                        item.source_name, err.message
                    ));
                    continue;
                }
                None => continue,
            };
            if expanded_sets.is_some() {
                builder.record_branch_count(item, &records);
            }
            builder.apply_records(item, &records, &mut next_frontier);
        }
        frontier = next_frontier;
    }

    Ok((hops, warnings))
}

/// Builds the hop-1 frontier items for the root function.
fn initial_frontier(
    root_id: &str,
    root_entry: &str,
    root_name: &str,
    inbound_depth: usize,
    outbound_depth: usize,
    interactive: bool,
) -> Vec<FrontierItem> {
    let mut items = Vec::new();
    let inbound_limit = if interactive {
        MAX_ALLOWED_DEPTH
    } else {
        inbound_depth
    };
    let outbound_limit = if interactive {
        MAX_ALLOWED_DEPTH
    } else {
        outbound_depth
    };
    if inbound_limit > 0 {
        items.push(FrontierItem {
            source_id: root_id.to_string(),
            source_entry: root_entry.to_string(),
            source_name: root_name.to_string(),
            arm: Arm::Callers,
            distance: 1,
            depth_limit: inbound_limit,
        });
    }
    if outbound_limit > 0 {
        items.push(FrontierItem {
            source_id: root_id.to_string(),
            source_entry: root_entry.to_string(),
            source_name: root_name.to_string(),
            arm: Arm::Callees,
            distance: 1,
            depth_limit: outbound_limit,
        });
    }
    items
}

impl Builder {
    /// Marks the branch expansion flag on `item.source_id` and returns `true` when expanded.
    fn mark_branch_state(
        &mut self,
        sets: &(HashSet<String>, HashSet<String>),
        item: &FrontierItem,
    ) -> bool {
        let is_expanded = match item.arm {
            Arm::Callers => sets.0.contains(&item.source_id),
            Arm::Callees => sets.1.contains(&item.source_id),
        };
        if let Some(&idx) = self.node_index.get(&item.source_id) {
            let branches = self.nodes[idx]
                .branches
                .get_or_insert_with(NodeBranches::default);
            let branch_state = BranchState {
                expanded: is_expanded,
                count: None,
            };
            match item.arm {
                Arm::Callers => branches.callers = Some(branch_state),
                Arm::Callees => branches.callees = Some(branch_state),
            }
        }
        is_expanded
    }

    /// Records the unique neighbor count onto an expanded branch.
    fn record_branch_count(&mut self, item: &FrontierItem, records: &[Value]) {
        let Some(&idx) = self.node_index.get(&item.source_id) else {
            return;
        };
        let unique: HashSet<String> = records
            .iter()
            .filter_map(|rec| non_empty_str(rec, "entry"))
            .map(canonical_id)
            .collect();
        let Some(branches) = self.nodes[idx].branches.as_mut() else {
            return;
        };
        let slot = match item.arm {
            Arm::Callers => branches.callers.as_mut(),
            Arm::Callees => branches.callees.as_mut(),
        };
        if let Some(state) = slot {
            state.count = Some(unique.len());
        }
    }

    /// Adds discovered nodes and edges from `records` and queues next-hop items.
    fn apply_records(
        &mut self,
        item: &FrontierItem,
        records: &[Value],
        next_frontier: &mut Vec<FrontierItem>,
    ) {
        for record in records {
            let Some(rec_entry) = non_empty_str(record, "entry") else {
                continue;
            };
            let target_id = canonical_id(rec_entry);
            let (from, to) = match item.arm {
                Arm::Callers => (target_id.clone(), item.source_id.clone()),
                Arm::Callees => (item.source_id.clone(), target_id.clone()),
            };
            let edge_key = (from.clone(), to.clone());
            if !self.edge_index.contains_key(&edge_key) && self.edges.len() >= self.max_edges {
                self.limited = true;
                continue;
            }

            let target_idx = if let Some(&idx) = self.node_index.get(&target_id) {
                idx
            } else {
                if self.nodes.len() >= self.max_nodes {
                    self.limited = true;
                    continue;
                }
                let idx = self.nodes.len();
                let name = non_empty_str(record, "name")
                    .unwrap_or(rec_entry)
                    .to_string();
                self.nodes.push(GraphNode {
                    id: target_id.clone(),
                    entry: rec_entry.to_string(),
                    name,
                    namespace: non_empty_str(record, "namespace").map(str::to_string),
                    demangled_name: non_empty_str(record, "demangled_name").map(str::to_string),
                    caller_distance: None,
                    callee_distance: None,
                    branches: None,
                });
                self.node_index.insert(target_id.clone(), idx);
                idx
            };

            if target_idx != 0 {
                match item.arm {
                    Arm::Callers => {
                        let dist = &mut self.nodes[target_idx].caller_distance;
                        *dist = Some(dist.map_or(item.distance, |prev| prev.min(item.distance)));
                    }
                    Arm::Callees => {
                        let dist = &mut self.nodes[target_idx].callee_distance;
                        *dist = Some(dist.map_or(item.distance, |prev| prev.min(item.distance)));
                    }
                }
            }

            let edge_idx = if let Some(&idx) = self.edge_index.get(&edge_key) {
                idx
            } else {
                let idx = self.edges.len();
                self.edges.push(GraphEdge {
                    from,
                    to,
                    sites: Vec::new(),
                });
                self.edge_index.insert(edge_key, idx);
                idx
            };
            if let Some(site) = non_empty_str(record, "call_site") {
                let sites = &mut self.edges[edge_idx].sites;
                if !sites.iter().any(|existing| existing == site) {
                    sites.push(site.to_string());
                }
            }

            let next_arms: &[Arm] = if self.interactive {
                &[Arm::Callers, Arm::Callees]
            } else {
                std::slice::from_ref(&item.arm)
            };
            for &arm in next_arms {
                let seen = match arm {
                    Arm::Callers => &mut self.seen_callers,
                    Arm::Callees => &mut self.seen_callees,
                };
                if seen.insert(target_id.clone()) {
                    if item.distance < item.depth_limit {
                        next_frontier.push(FrontierItem {
                            source_id: target_id.clone(),
                            source_entry: self.nodes[target_idx].entry.clone(),
                            source_name: self.nodes[target_idx].name.clone(),
                            arm,
                            distance: item.distance + 1,
                            depth_limit: item.depth_limit,
                        });
                    } else if self.interactive {
                        self.limited = true;
                    }
                }
            }
        }
    }
}

/// Returns a trimmed non-empty string field from `obj`.
fn non_empty_str<'a>(obj: &'a Value, field: &str) -> Option<&'a str> {
    obj.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
