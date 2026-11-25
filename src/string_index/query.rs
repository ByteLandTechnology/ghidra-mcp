// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Request validation, filter evaluation, projection, and signed cursors for `search.strings`.

use super::{CachedStringItem, StringIndexSnapshot};
use crate::error::DomainError;
use crate::string_regexp::{CompiledRegex, RegexError};
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Default page limit for `search.strings`.
const DEFAULT_PAGE_LIMIT: usize = 100;
/// Maximum page limit for `search.strings`.
const MAX_PAGE_LIMIT: usize = 1000;
/// Maximum string query byte length accepted by `search.strings`.
const MAX_STRING_QUERY_BYTES: usize = 4096;
/// Cursor domain tag for daemon-served `search.strings` pages.
const CURSOR_DOMAIN: &str = "ghidra-mcp-search-strings-v1";
/// URL-safe Base64 alphabet without `=` pad characters.
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Validated `search.strings` request parameters.
pub(super) struct ParsedStringRequest {
    /// Plain-text query, if non-blank.
    pub query: Option<String>,
    /// Regular expression pattern text, if present.
    pub regex: Option<String>,
    /// `true` for case-sensitive text or regular expression evaluation.
    pub case_sensitive: bool,
    /// Encoding filter (`all`, `ascii`, `utf16`, `utf16le`, `utf16be`).
    pub encoding: String,
    /// Optional defined-only or undefined-only filter.
    pub defined: Option<bool>,
    /// Minimum UTF-16 code unit length (`1..=4096`).
    pub min_length: usize,
    /// Page size (`1..=1000`).
    pub limit: usize,
    /// Optional pagination cursor token.
    pub cursor: Option<String>,
    /// Optional canonical address range `(start, end)`.
    pub canonical_range: Option<(Option<String>, Option<String>)>,
    /// `true` if `scan.range` holds a non-canonical address that needs bridge evaluation.
    pub non_canonical_range: bool,
    /// Optional selected output fields (`projection.fields`).
    pub projected_fields: Option<Vec<String>>,
    /// Query fingerprint for cursor validation.
    pub fingerprint: String,
}

/// Plain-text predicate for `filter.query`.
enum SubstringMatcher {
    /// Case-sensitive text containment check.
    Exact(String),
    /// Case-insensitive text containment check with lowercase needle.
    Lower(String),
}

/// Compiled matcher for string values.
pub(super) struct StringMatcher {
    /// Optional plain-text containment predicate.
    substring: Option<SubstringMatcher>,
    /// Optional compiled regular expression predicate.
    regex: Option<CompiledRegex>,
}

impl StringMatcher {
    /// Returns `true` if `value` satisfies the text and regular expression filters.
    fn matches(&self, value: &str) -> bool {
        if let Some(sub) = &self.substring {
            let ok = match sub {
                SubstringMatcher::Exact(needle) => value.contains(needle.as_str()),
                SubstringMatcher::Lower(needle) => contains_case_insensitive(value, needle),
            };
            if !ok {
                return false;
            }
        }
        if let Some(compiled) = &self.regex {
            if !compiled.is_match(value) {
                return false;
            }
        }
        true
    }
}

/// Builds the string value matcher from `parsed`.
pub(super) fn build_matcher(
    parsed: &ParsedStringRequest,
) -> std::result::Result<StringMatcher, RegexError> {
    let substring = parsed.query.as_ref().map(|query| {
        if parsed.case_sensitive {
            SubstringMatcher::Exact(query.clone())
        } else {
            SubstringMatcher::Lower(query.to_lowercase())
        }
    });
    let regex = match &parsed.regex {
        Some(pattern) => Some(CompiledRegex::compile(pattern, parsed.case_sensitive)?),
        None => None,
    };
    Ok(StringMatcher { substring, regex })
}

/// Filters, paginates, and projects a response page from `snapshot`.
pub(super) fn evaluate_from_snapshot(
    snapshot: &StringIndexSnapshot,
    request: &ParsedStringRequest,
    matcher: &StringMatcher,
    resume_after: Option<&str>,
    md5: &str,
    cursor_secret: &[u8; 32],
) -> Value {
    let mut page_items: Vec<&CachedStringItem> = Vec::new();
    let mut next_address: Option<String> = None;

    for item in &snapshot.items {
        if let Some(last) = resume_after {
            if item.address.as_str() <= last {
                continue;
            }
        }
        if !matches_item(item, request, matcher) {
            continue;
        }
        if page_items.len() >= request.limit {
            if let Some(last_item) = page_items.last() {
                next_address = Some(last_item.address.clone());
            }
            break;
        }
        page_items.push(item);
    }

    let encoded_items: Vec<Value> = page_items
        .into_iter()
        .map(|item| serialize_projected_item(item, request.projected_fields.as_deref()))
        .collect();

    let mut out = Map::new();
    out.insert("items".into(), Value::Array(encoded_items));
    if let Some(last) = next_address {
        let token = encode_cursor(md5, &request.fingerprint, &last, cursor_secret);
        out.insert("next_cursor".into(), Value::String(token));
    }
    out.insert("index_complete".into(), Value::Bool(true));
    out.insert("total_indexed".into(), json!(snapshot.total_indexed));
    out.insert(
        "modification_number".into(),
        json!(snapshot.modification_number),
    );
    Value::Object(out)
}

/// Checks whether `item` passes all filter and range predicates in `request`.
fn matches_item(
    item: &CachedStringItem,
    request: &ParsedStringRequest,
    matcher: &StringMatcher,
) -> bool {
    match request.encoding.as_str() {
        "all" => {}
        "utf16" => {
            if item.encoding != "utf16le" && item.encoding != "utf16be" {
                return false;
            }
        }
        expected => {
            if item.encoding != expected {
                return false;
            }
        }
    }
    if let Some(defined) = request.defined {
        if item.defined != defined {
            return false;
        }
    }
    if request.min_length > 1 && item.value.encode_utf16().count() < request.min_length {
        return false;
    }
    if let Some((start, end)) = &request.canonical_range {
        if let Some(start_addr) = start {
            if compare_canonical_address(&item.address, start_addr).is_lt() {
                return false;
            }
        }
        if let Some(end_addr) = end {
            if compare_canonical_address(&item.address, end_addr).is_gt() {
                return false;
            }
        }
    }
    matcher.matches(&item.value)
}

/// Serializes one [`CachedStringItem`] and selects `projection.fields` when present.
fn serialize_projected_item(item: &CachedStringItem, fields: Option<&[String]>) -> Value {
    let mut full = Map::new();
    full.insert("address".into(), json!(item.address));
    full.insert("value".into(), json!(item.value));
    full.insert("length".into(), json!(item.length));
    full.insert("encoding".into(), json!(item.encoding));
    full.insert("defined".into(), json!(item.defined));
    if let Some(dt) = &item.data_type {
        full.insert("data_type".into(), dt.clone());
    }
    let Some(selected) = fields else {
        return Value::Object(full);
    };
    let mut projected = Map::new();
    projected.insert("address".into(), json!(item.address));
    for field in selected {
        if field == "address" {
            continue;
        }
        if let Some(val) = full.get(field) {
            projected.insert(field.clone(), val.clone());
        }
    }
    Value::Object(projected)
}

/// Case-insensitive text containment check on a lowercase `lower_needle`.
fn contains_case_insensitive(haystack: &str, lower_needle: &str) -> bool {
    if lower_needle.is_empty() {
        return true;
    }
    if haystack.is_ascii() && lower_needle.is_ascii() {
        let hay = haystack.as_bytes();
        let ndl = lower_needle.as_bytes();
        if ndl.len() > hay.len() {
            return false;
        }
        return hay
            .windows(ndl.len())
            .any(|win| win.eq_ignore_ascii_case(ndl));
    }
    haystack.to_lowercase().contains(lower_needle)
}

/// Validated `filter` fields for `search.strings`.
struct ParsedFilter {
    /// Plain-text query, if non-blank.
    query: Option<String>,
    /// Regular expression pattern text, if present.
    regex: Option<String>,
    /// `true` for case-sensitive evaluation.
    case_sensitive: bool,
    /// Encoding filter (`all`, `ascii`, `utf16`, `utf16le`, `utf16be`).
    encoding: String,
    /// Optional defined-only or undefined-only filter.
    defined: Option<bool>,
    /// Minimum UTF-16 code unit length (`1..=4096`).
    min_length: usize,
}

/// Validates `search.strings` parameters against the bridge contract.
pub(super) fn parse_string_request(params: &Value) -> Result<ParsedStringRequest> {
    let obj = params
        .as_object()
        .ok_or_else(|| DomainError::invalid_argument("params", "params must be an object"))?;
    for key in obj.keys() {
        if !matches!(key.as_str(), "filter" | "page" | "projection" | "scan") {
            return Err(DomainError::invalid_argument(
                format!("/{key}"),
                format!("unexpected field `{key}` in params"),
            )
            .into());
        }
    }
    let filter = parse_filter(obj.get("filter"))?;
    let (limit, cursor) = parse_page(obj.get("page"))?;
    let (canonical_range, non_canonical_range) = parse_scan(obj.get("scan"))?;
    let projected_fields = parse_projection(obj.get("projection"))?;
    let fingerprint = compute_query_fingerprint(
        filter.query.as_deref(),
        filter.regex.as_deref(),
        filter.case_sensitive,
        &filter.encoding,
        filter.defined,
        filter.min_length,
        canonical_range.as_ref(),
    );

    Ok(ParsedStringRequest {
        query: filter.query,
        regex: filter.regex,
        case_sensitive: filter.case_sensitive,
        encoding: filter.encoding,
        defined: filter.defined,
        min_length: filter.min_length,
        limit,
        cursor,
        canonical_range,
        non_canonical_range,
        projected_fields,
        fingerprint,
    })
}

/// Parses and validates `filter` parameters.
fn parse_filter(filter_val: Option<&Value>) -> Result<ParsedFilter> {
    let mut out = ParsedFilter {
        query: None,
        regex: None,
        case_sensitive: false,
        encoding: "all".to_string(),
        defined: None,
        min_length: 1,
    };
    let Some(raw_filter) = filter_val else {
        return Ok(out);
    };
    let filter = require_known_object(
        raw_filter,
        "/filter",
        &[
            "query",
            "regex",
            "case_sensitive",
            "encoding",
            "defined",
            "min_length",
        ],
    )?;
    if let Some(q) = filter.get("query") {
        let text = q.as_str().ok_or_else(|| {
            DomainError::invalid_argument("/filter/query", "/filter/query must be a string")
        })?;
        if text.len() > MAX_STRING_QUERY_BYTES {
            return Err(DomainError::invalid_argument(
                "/filter/query",
                format!("/filter/query exceeds {MAX_STRING_QUERY_BYTES} bytes"),
            )
            .into());
        }
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            out.query = Some(trimmed.to_string());
        }
    }
    if let Some(r) = filter.get("regex") {
        out.regex = Some(parse_regex_filter(r)?);
    }
    if let Some(cs) = filter.get("case_sensitive") {
        out.case_sensitive = cs.as_bool().ok_or_else(|| {
            DomainError::invalid_argument(
                "/filter/case_sensitive",
                "/filter/case_sensitive must be a boolean",
            )
        })?;
    }
    if let Some(enc) = filter.get("encoding") {
        let raw = enc.as_str().ok_or_else(|| {
            DomainError::invalid_argument("/filter/encoding", "/filter/encoding must be a string")
        })?;
        if !matches!(raw, "all" | "ascii" | "utf16" | "utf16le" | "utf16be") {
            return Err(DomainError::invalid_argument(
                "/filter/encoding",
                "unsupported encoding filter",
            )
            .into());
        }
        out.encoding = raw.to_string();
    }
    if let Some(def) = filter.get("defined") {
        out.defined = Some(def.as_bool().ok_or_else(|| {
            DomainError::invalid_argument("/filter/defined", "/filter/defined must be a boolean")
        })?);
    }
    if let Some(ml) = filter.get("min_length") {
        let num = ml.as_i64().ok_or_else(|| {
            DomainError::invalid_argument(
                "/filter/min_length",
                "/filter/min_length must be an integer",
            )
        })?;
        let max_len = i64::try_from(MAX_STRING_QUERY_BYTES).unwrap_or(4096);
        if !(1..=max_len).contains(&num) {
            return Err(DomainError::invalid_argument(
                "/filter/min_length",
                format!("/filter/min_length must be between 1 and {MAX_STRING_QUERY_BYTES}"),
            )
            .into());
        }
        out.min_length = usize::try_from(num).unwrap_or(1);
    }
    Ok(out)
}

/// Validates a `filter.regex` field as a non-blank bounded pattern string.
fn parse_regex_filter(raw: &Value) -> Result<String> {
    let pattern = raw.as_str().ok_or_else(|| {
        DomainError::invalid_argument("/filter/regex", "/filter/regex must be a string")
    })?;
    if pattern.trim().is_empty() {
        return Err(DomainError::invalid_argument(
            "/filter/regex",
            "/filter/regex must not be blank",
        )
        .into());
    }
    if pattern.len() > MAX_STRING_QUERY_BYTES {
        return Err(DomainError::invalid_argument(
            "/filter/regex",
            format!("/filter/regex exceeds {MAX_STRING_QUERY_BYTES} bytes"),
        )
        .into());
    }
    Ok(pattern.to_string())
}

/// Parses and validates `page` (`limit` and `cursor`).
fn parse_page(page_val: Option<&Value>) -> Result<(usize, Option<String>)> {
    let Some(val) = page_val else {
        return Ok((DEFAULT_PAGE_LIMIT, None));
    };
    let page = require_known_object(val, "/page", &["limit", "cursor"])?;
    let mut limit = DEFAULT_PAGE_LIMIT;
    if let Some(raw_limit) = page.get("limit") {
        let num = raw_limit.as_i64().ok_or_else(|| {
            DomainError::invalid_argument("/page/limit", "/page/limit must be an integer")
        })?;
        let max_limit = i64::try_from(MAX_PAGE_LIMIT).unwrap_or(1000);
        if !(1..=max_limit).contains(&num) {
            return Err(DomainError::invalid_argument(
                "/page/limit",
                format!("/page/limit must be between 1 and {MAX_PAGE_LIMIT}"),
            )
            .into());
        }
        limit = usize::try_from(num).unwrap_or(DEFAULT_PAGE_LIMIT);
    }
    let cursor = match page.get("cursor") {
        Some(raw_cursor) => {
            let token = raw_cursor.as_str().ok_or_else(|| {
                DomainError::invalid_argument("/page/cursor", "/page/cursor must be a string")
            })?;
            if token.trim().is_empty() {
                return Err(DomainError::invalid_argument(
                    "/page/cursor",
                    "/page/cursor must not be blank",
                )
                .into());
            }
            Some(token.to_string())
        }
        None => None,
    };
    Ok((limit, cursor))
}

/// Parses and validates `scan` (`range` and `timeout_ms`).
#[expect(
    clippy::type_complexity,
    reason = "returns optional canonical bounds and a bridge fallback flag"
)]
fn parse_scan(
    scan_val: Option<&Value>,
) -> Result<(Option<(Option<String>, Option<String>)>, bool)> {
    let Some(val) = scan_val else {
        return Ok((None, false));
    };
    let scan = require_known_object(val, "/scan", &["range", "timeout_ms"])?;
    if let Some(timeout) = scan.get("timeout_ms") {
        let ms = timeout.as_i64().ok_or_else(|| {
            DomainError::invalid_argument("/scan/timeout_ms", "/scan/timeout_ms must be an integer")
        })?;
        if !(100..=60_000).contains(&ms) {
            return Err(DomainError::invalid_argument(
                "/scan/timeout_ms",
                "/scan/timeout_ms must be between 100 and 60000",
            )
            .into());
        }
    }
    let Some(range_val) = scan.get("range") else {
        return Ok((None, false));
    };
    let range = require_known_object(range_val, "/scan/range", &["start", "end"])?;
    let start = optional_non_blank_str(range.get("start"), "/scan/range/start")?;
    let end = optional_non_blank_str(range.get("end"), "/scan/range/end")?;
    if start.is_none() && end.is_none() {
        return Ok((None, false));
    }
    let start_ok = start.as_deref().is_none_or(is_canonical_address);
    let end_ok = end.as_deref().is_none_or(is_canonical_address);
    if !start_ok || !end_ok {
        return Ok((None, true));
    }
    if let (Some(s), Some(e)) = (&start, &end) {
        if same_space(s, e) && compare_canonical_address(s, e).is_gt() {
            return Err(DomainError::invalid_argument(
                "/scan/range",
                "scan range start exceeds end",
            )
            .into());
        }
        if !same_space(s, e) {
            return Ok((None, true));
        }
    }
    Ok((Some((start, end)), false))
}

/// Parses and validates `projection.fields`.
fn parse_projection(proj_val: Option<&Value>) -> Result<Option<Vec<String>>> {
    let Some(val) = proj_val else {
        return Ok(None);
    };
    let proj = require_known_object(val, "/projection", &["fields"])?;
    let Some(fields_val) = proj.get("fields") else {
        return Ok(None);
    };
    let arr = fields_val.as_array().ok_or_else(|| {
        DomainError::invalid_argument("/projection/fields", "/projection/fields must be an array")
    })?;
    if arr.is_empty() || arr.len() > 256 {
        return Err(DomainError::invalid_argument(
            "/projection/fields",
            "/projection/fields must hold 1 to 256 items",
        )
        .into());
    }
    let known = [
        "address",
        "value",
        "length",
        "encoding",
        "defined",
        "data_type",
    ];
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let target = format!("/projection/fields/{idx}");
        let Some(name) = item.as_str() else {
            return Err(
                DomainError::invalid_argument(&target, format!("{target} is invalid")).into(),
            );
        };
        if name.trim().is_empty() || !known.contains(&name) {
            return Err(DomainError::invalid_argument(
                &target,
                format!("{name} is not selectable"),
            )
            .into());
        }
        if !seen.insert(name.to_string()) {
            return Err(
                DomainError::invalid_argument(&target, format!("{name} is duplicated")).into(),
            );
        }
        out.push(name.to_string());
    }
    Ok(Some(out))
}

/// Checks that `value` is a JSON object with only `known` keys.
fn require_known_object<'a>(
    value: &'a Value,
    target: &str,
    known: &[&str],
) -> Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or_else(|| {
        DomainError::invalid_argument(target, format!("{target} must be an object"))
    })?;
    for key in map.keys() {
        if !known.contains(&key.as_str()) {
            return Err(DomainError::invalid_argument(
                format!("{target}/{key}"),
                format!("unexpected field `{key}` in {target}"),
            )
            .into());
        }
    }
    Ok(map)
}

/// Extracts an optional non-blank string field.
fn optional_non_blank_str(value: Option<&Value>, target: &str) -> Result<Option<String>> {
    let Some(v) = value else {
        return Ok(None);
    };
    let s = v.as_str().ok_or_else(|| {
        DomainError::invalid_argument(target, format!("{target} must be a string"))
    })?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

/// Returns `true` if `address` is in Ghidra canonical `space:hex` lowercase form.
fn is_canonical_address(address: &str) -> bool {
    let Some((space, hex)) = address.rsplit_once(':') else {
        return false;
    };
    !space.is_empty()
        && hex.len() >= 8
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Returns `true` if two canonical addresses belong to the same address space.
fn same_space(left: &str, right: &str) -> bool {
    left.rsplit_once(':').map(|(s, _)| s) == right.rsplit_once(':').map(|(s, _)| s)
}

/// Compares two canonical `space:hex` addresses numerically within each space.
pub(super) fn compare_canonical_address(left: &str, right: &str) -> std::cmp::Ordering {
    let (Some((ls, lh)), Some((rs, rh))) = (left.rsplit_once(':'), right.rsplit_once(':')) else {
        return left.cmp(right);
    };
    let by_space = ls.cmp(rs);
    if by_space != std::cmp::Ordering::Equal {
        return by_space;
    }
    let lt = lh.trim_start_matches('0');
    let rt = rh.trim_start_matches('0');
    lt.len().cmp(&rt.len()).then_with(|| lt.cmp(rt))
}

/// Calculates a deterministic query fingerprint for cursor validation.
fn compute_query_fingerprint(
    query: Option<&str>,
    regex: Option<&str>,
    case_sensitive: bool,
    encoding: &str,
    defined: Option<bool>,
    min_length: usize,
    range: Option<&(Option<String>, Option<String>)>,
) -> String {
    let mut ctx = md5::Context::new();
    let q = query.unwrap_or("");
    let r = regex.unwrap_or("");
    ctx.consume(q.len().to_le_bytes());
    ctx.consume(q.as_bytes());
    ctx.consume(r.len().to_le_bytes());
    ctx.consume(r.as_bytes());
    ctx.consume([u8::from(case_sensitive)]);
    ctx.consume(encoding.as_bytes());
    ctx.consume([match defined {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }]);
    ctx.consume(min_length.to_le_bytes());
    if let Some((start, end)) = range {
        ctx.consume(b"range:");
        ctx.consume(start.as_deref().unwrap_or("").as_bytes());
        ctx.consume(b"..");
        ctx.consume(end.as_deref().unwrap_or("").as_bytes());
    }
    format!("{:x}", ctx.finalize())
}

/// Encodes an opaque signed pagination cursor.
fn encode_cursor(md5: &str, fingerprint: &str, last_address: &str, secret: &[u8; 32]) -> String {
    let payload = format!("search.strings\n{md5}\n{fingerprint}\n{last_address}");
    let sig = sign_cursor(&payload, secret);
    let wire = format!("{payload}\n{sig}");
    base64_url_encode(wire.as_bytes())
}

/// Decodes and verifies a pagination cursor from a client request.
pub(super) fn decode_cursor(
    token: &str,
    md5: &str,
    fingerprint: &str,
    secret: &[u8; 32],
) -> Result<String> {
    let invalid = || DomainError::invalid_argument("/page/cursor", "cursor is invalid");
    let raw = base64_url_decode(token).ok_or_else(invalid)?;
    let wire = String::from_utf8(raw).map_err(|_| invalid())?;
    let parts: Vec<&str> = wire.split('\n').collect();
    if parts.len() != 5 {
        return Err(invalid().into());
    }
    let payload = format!("{}\n{}\n{}\n{}", parts[0], parts[1], parts[2], parts[3]);
    let expected = sign_cursor(&payload, secret);
    if expected != parts[4]
        || parts[0] != "search.strings"
        || parts[1] != md5
        || parts[2] != fingerprint
        || parts[3].is_empty()
    {
        return Err(invalid().into());
    }
    Ok(parts[3].to_string())
}

/// Calculates a keyed digest tag for `payload`.
fn sign_cursor(payload: &str, secret: &[u8; 32]) -> String {
    let mut inner = md5::Context::new();
    inner.consume(secret);
    inner.consume(CURSOR_DOMAIN.as_bytes());
    inner.consume(b"\n");
    inner.consume(payload.as_bytes());
    let inner_digest = inner.finalize();

    let mut outer = md5::Context::new();
    for byte in secret {
        outer.consume([byte ^ 0x5c]);
    }
    outer.consume(inner_digest.0);
    format!("{:x}", outer.finalize())
}

/// Encodes `bytes` as unpadded URL-safe Base64.
fn base64_url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(BASE64_URL[usize::from(b0 >> 2)]));
        out.push(char::from(
            BASE64_URL[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64_URL[usize::from(((b1 & 0x0f) << 2) | (b2 >> 6))],
            ));
        }
        if chunk.len() > 2 {
            out.push(char::from(BASE64_URL[usize::from(b2 & 0x3f)]));
        }
    }
    out
}

/// Decodes unpadded or `=`-padded URL-safe or standard Base64.
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    if trimmed.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity((trimmed.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for byte in trimmed.bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}
