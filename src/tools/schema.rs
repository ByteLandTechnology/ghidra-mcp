// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Builds compact, provider-safe `params` schemas for MCP `tools/list`.
//!
//! Public `tools/list` definitions omit `oneOf`, `anyOf`, `allOf`, `$ref`,
//! `$defs`, and `additionalProperties` at every depth so strict providers such
//! as Gemini accept each tool declaration.

use super::catalog::Operation;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Maximum object depth for single-operation domain tools.
const SINGLE_OPERATION_MAX_DEPTH: usize = 4;

/// Maximum object depth for multi-operation summaries and `batch`.
const SUMMARY_MAX_DEPTH: usize = 2;

/// Internal reference URI for recursive Ghidra data type references.
const DATA_TYPE_REF: &str = "#/$defs/data_type_reference";

/// Scalar JSON Schema keywords copied onto flattened leaf nodes.
const SCALAR_KEYS: &[&str] = &[
    "description",
    "enum",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "default",
];

/// Builds the compact `params` schema for `domain_name` and `operations`.
pub(super) fn params_schema(domain_name: &str, operations: &[Operation]) -> Value {
    let max_depth = if operations.len() == 1 && domain_name != "batch" {
        SINGLE_OPERATION_MAX_DEPTH
    } else {
        SUMMARY_MAX_DEPTH
    };
    let flattened: Vec<Value> = operations
        .iter()
        .map(|operation| flatten(&operation.schema, 0, max_depth))
        .collect();
    let merged = if flattened.len() == 1 {
        flattened.into_iter().next().unwrap_or_default()
    } else {
        merge_schemas(&flattened)
    };

    let description = if operations.len() == 1 {
        "The parameters for the operation."
    } else {
        concat!(
            "The parameters summary for the domain. Call ghidra_help with the domain ",
            "for the exact schema of each operation."
        )
    };

    let mut params = Map::new();
    params.insert("type".into(), json!("object"));
    params.insert("description".into(), json!(description));
    let properties = merged
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    params.insert("properties".into(), Value::Object(properties));
    if let Some(required) = merged.get("required").and_then(Value::as_array) {
        if !required.is_empty() {
            params.insert("required".into(), Value::Array(required.clone()));
        }
    }
    Value::Object(params)
}

/// Flattens one JSON Schema node without union, reference, or extra-property keys.
fn flatten(schema: &Value, depth: usize, max_depth: usize) -> Value {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return flatten_reference(reference, depth, max_depth);
    }
    if let Some(branches) = union_branches(schema) {
        let non_null: Vec<Value> = branches
            .iter()
            .filter(|branch| branch.get("type").and_then(Value::as_str) != Some("null"))
            .map(|branch| flatten(branch, depth, max_depth))
            .collect();
        return match non_null.len() {
            0 => Value::Object(Map::new()),
            1 => non_null.into_iter().next().unwrap_or_default(),
            _ => merge_schemas(&non_null),
        };
    }
    let Some(schema_type) = schema.get("type").and_then(Value::as_str) else {
        return copy_description_only(schema);
    };
    match schema_type {
        "object" => flatten_object(schema, depth, max_depth),
        "array" => flatten_array(schema, depth, max_depth),
        "string" | "integer" | "number" | "boolean" => flatten_scalar(schema, schema_type),
        other => json!({ "type": other }),
    }
}

/// Expands a recursive data type reference down to `max_depth`.
fn flatten_reference(reference: &str, depth: usize, max_depth: usize) -> Value {
    if reference != DATA_TYPE_REF || depth >= max_depth {
        return json!({ "type": "object" });
    }
    let mut properties = Map::new();
    properties.insert(
        "kind".into(),
        json!({
            "type": "string",
            "enum": ["array", "named", "pointer", "untyped_pointer"]
        }),
    );
    properties.insert("name".into(), json!({ "type": "string", "minLength": 1 }));
    properties.insert(
        "target".into(),
        flatten_reference(reference, depth + 1, max_depth),
    );
    properties.insert(
        "element".into(),
        flatten_reference(reference, depth + 1, max_depth),
    );
    properties.insert(
        "count".into(),
        json!({ "type": "integer", "minimum": 1, "maximum": i32::MAX }),
    );
    json!({
        "type": "object",
        "properties": properties,
        "required": ["kind"]
    })
}

/// Flattens an object schema up to `max_depth`.
fn flatten_object(schema: &Value, depth: usize, max_depth: usize) -> Value {
    if schema.get("additionalProperties") == Some(&Value::Bool(true)) {
        return with_description(json!({ "type": "object" }), schema);
    }
    let Some(raw_properties) = schema.get("properties").and_then(Value::as_object) else {
        return with_description(json!({ "type": "object" }), schema);
    };
    if depth >= max_depth {
        if raw_properties.is_empty() {
            return with_description(json!({ "type": "object", "properties": {} }), schema);
        }
        return with_description(json!({ "type": "object" }), schema);
    }
    let mut properties = Map::new();
    for (key, child) in raw_properties {
        properties.insert(key.clone(), flatten(child, depth + 1, max_depth));
    }
    let mut result = Map::new();
    result.insert("type".into(), json!("object"));
    copy_if_present(schema, &mut result, "description");
    result.insert("properties".into(), Value::Object(properties));
    copy_if_present(schema, &mut result, "minProperties");
    copy_if_present(schema, &mut result, "maxProperties");
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        if !required.is_empty() {
            result.insert("required".into(), Value::Array(required.clone()));
        }
    }
    Value::Object(result)
}

/// Flattens an array schema and its item schema.
fn flatten_array(schema: &Value, depth: usize, max_depth: usize) -> Value {
    let mut result = Map::new();
    result.insert("type".into(), json!("array"));
    copy_if_present(schema, &mut result, "description");
    if let Some(items) = schema.get("items") {
        result.insert("items".into(), flatten(items, depth, max_depth));
    }
    copy_if_present(schema, &mut result, "minItems");
    copy_if_present(schema, &mut result, "maxItems");
    Value::Object(result)
}

/// Copies provider-safe keywords onto a scalar schema node.
fn flatten_scalar(schema: &Value, schema_type: &str) -> Value {
    let mut result = Map::new();
    result.insert("type".into(), json!(schema_type));
    for key in SCALAR_KEYS {
        copy_if_present(schema, &mut result, key);
    }
    Value::Object(result)
}

/// Merges two or more flattened schemas into one union-free schema.
fn merge_schemas(schemas: &[Value]) -> Value {
    let Some(common_type) = common_type(schemas) else {
        return Value::Object(Map::new());
    };
    match common_type {
        "object" => merge_objects(schemas),
        "array" => merge_arrays(schemas),
        "string" => merge_strings(schemas),
        "integer" | "number" => merge_numbers(schemas, common_type),
        "boolean" => merge_booleans(schemas),
        other => json!({ "type": other }),
    }
}

/// Merges object schemas from the union of properties and intersection of required keys.
fn merge_objects(schemas: &[Value]) -> Value {
    if schemas
        .iter()
        .any(|schema| !schema.get("properties").is_some_and(Value::is_object))
    {
        return json!({ "type": "object" });
    }
    let mut keys: Vec<String> = Vec::new();
    for schema in schemas {
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for key in properties.keys() {
                if !keys.contains(key) {
                    keys.push(key.clone());
                }
            }
        }
    }
    let mut merged_properties = Map::new();
    for key in keys {
        let bucket: Vec<Value> = schemas
            .iter()
            .filter_map(|schema| schema.get("properties")?.get(&key).cloned())
            .collect();
        let merged_child = if bucket.len() == 1 {
            bucket.into_iter().next().unwrap_or_default()
        } else {
            merge_schemas(&bucket)
        };
        merged_properties.insert(key, merged_child);
    }

    let required = intersect_required(schemas);
    let mut result = Map::new();
    result.insert("type".into(), json!("object"));
    put_shared_scalar(schemas, &mut result, "description");
    result.insert("properties".into(), Value::Object(merged_properties));
    put_merged_bound(schemas, &mut result, "minProperties", true);
    put_merged_bound(schemas, &mut result, "maxProperties", false);
    if !required.is_empty() {
        result.insert("required".into(), json!(required));
    }
    Value::Object(result)
}

/// Returns the required property names shared by every schema in `schemas`.
fn intersect_required(schemas: &[Value]) -> Vec<String> {
    let Some((first, rest)) = schemas.split_first() else {
        return Vec::new();
    };
    let mut common: Vec<String> = first
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    for schema in rest {
        let branch: BTreeSet<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        common.retain(|item| branch.contains(item.as_str()));
    }
    common
}

/// Merges array schemas from their item schemas and bounds.
fn merge_arrays(schemas: &[Value]) -> Value {
    let mut result = Map::new();
    result.insert("type".into(), json!("array"));
    put_shared_scalar(schemas, &mut result, "description");
    let items: Vec<Value> = schemas
        .iter()
        .filter_map(|schema| schema.get("items").cloned())
        .collect();
    if !items.is_empty() {
        let merged_items = if items.len() == 1 {
            items.into_iter().next().unwrap_or_default()
        } else {
            merge_schemas(&items)
        };
        result.insert("items".into(), merged_items);
    }
    put_merged_bound(schemas, &mut result, "minItems", true);
    put_merged_bound(schemas, &mut result, "maxItems", false);
    Value::Object(result)
}

/// Merges string schemas and unions `enum` values when every branch restricts them.
fn merge_strings(schemas: &[Value]) -> Value {
    let mut result = Map::new();
    result.insert("type".into(), json!("string"));
    put_shared_scalar(schemas, &mut result, "description");
    if schemas
        .iter()
        .all(|schema| schema.get("enum").is_some_and(Value::is_array))
    {
        let mut values = BTreeSet::new();
        for schema in schemas {
            if let Some(items) = schema.get("enum").and_then(Value::as_array) {
                for item in items.iter().filter_map(Value::as_str) {
                    values.insert(item.to_string());
                }
            }
        }
        result.insert("enum".into(), json!(values));
    }
    put_merged_bound(schemas, &mut result, "minLength", true);
    put_merged_bound(schemas, &mut result, "maxLength", false);
    put_shared_scalar(schemas, &mut result, "pattern");
    put_shared_scalar(schemas, &mut result, "default");
    Value::Object(result)
}

/// Merges integer or number schemas.
fn merge_numbers(schemas: &[Value], schema_type: &str) -> Value {
    let mut result = Map::new();
    result.insert("type".into(), json!(schema_type));
    put_shared_scalar(schemas, &mut result, "description");
    put_merged_bound(schemas, &mut result, "minimum", true);
    put_merged_bound(schemas, &mut result, "maximum", false);
    put_shared_scalar(schemas, &mut result, "default");
    Value::Object(result)
}

/// Merges boolean schemas.
fn merge_booleans(schemas: &[Value]) -> Value {
    let mut result = Map::new();
    result.insert("type".into(), json!("boolean"));
    put_shared_scalar(schemas, &mut result, "description");
    put_shared_scalar(schemas, &mut result, "default");
    Value::Object(result)
}

/// Extracts union branches from `oneOf`, `anyOf`, or `allOf` when present.
fn union_branches(schema: &Value) -> Option<&[Value]> {
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(list) = schema.get(keyword).and_then(Value::as_array) {
            return Some(list.as_slice());
        }
    }
    None
}

/// Returns the shared `type` string when every schema in `schemas` has the same type.
fn common_type(schemas: &[Value]) -> Option<&str> {
    let first = schemas.first()?.get("type")?.as_str()?;
    schemas
        .iter()
        .all(|schema| schema.get("type").and_then(Value::as_str) == Some(first))
        .then_some(first)
}

/// Inserts the minimum or maximum numeric bound when every branch defines `key`.
fn put_merged_bound(
    schemas: &[Value],
    target: &mut Map<String, Value>,
    key: &str,
    take_minimum: bool,
) {
    let mut int_bound: Option<i64> = None;
    let mut float_bound: Option<f64> = None;
    let mut is_float = false;
    for schema in schemas {
        let Some(value) = schema.get(key) else {
            return;
        };
        if let Some(integer) = value.as_i64() {
            int_bound = Some(int_bound.map_or(integer, |current| {
                if take_minimum {
                    current.min(integer)
                } else {
                    current.max(integer)
                }
            }));
        } else if let Some(number) = value.as_f64() {
            is_float = true;
            float_bound = Some(float_bound.map_or(number, |current| {
                if take_minimum {
                    current.min(number)
                } else {
                    current.max(number)
                }
            }));
        } else {
            return;
        }
    }
    if is_float {
        if let Some(bound) = float_bound {
            target.insert(key.into(), json!(bound));
        }
    } else if let Some(bound) = int_bound {
        target.insert(key.into(), json!(bound));
    }
}

/// Copies `key` into `target` when all branches that define `key` have the same value.
fn put_shared_scalar(schemas: &[Value], target: &mut Map<String, Value>, key: &str) {
    let mut shared: Option<&Value> = None;
    for schema in schemas {
        let Some(candidate) = schema.get(key) else {
            continue;
        };
        match shared {
            None => shared = Some(candidate),
            Some(previous) if previous == candidate => {}
            Some(_) => return,
        }
    }
    if let Some(value) = shared {
        target.insert(key.into(), value.clone());
    }
}

/// Copies only `description` when a schema node has no explicit `type`.
fn copy_description_only(schema: &Value) -> Value {
    let mut result = Map::new();
    copy_if_present(schema, &mut result, "description");
    Value::Object(result)
}

/// Adds `description` from `source` to `base` when present.
fn with_description(mut base: Value, source: &Value) -> Value {
    if let (Some(map), Some(description)) = (base.as_object_mut(), source.get("description")) {
        map.insert("description".into(), description.clone());
    }
    base
}

/// Copies `key` from `source` to `target` when present.
fn copy_if_present(source: &Value, target: &mut Map<String, Value>, key: &str) {
    if let Some(value) = source.get(key) {
        target.insert(key.into(), value.clone());
    }
}
