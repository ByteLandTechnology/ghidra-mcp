// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Strict JSON-RPC 2.0 codec for the bridge WebSocket.
//!
//! The daemon sends requests with `jsonrpc`, a string `id`, `method` and an
//! object `params`. The bridge sends two types of messages:
//!
//! - The `ghidra.ready` notification, sent once to complete its handshake:
//!   `{"jsonrpc":"2.0","method":"ghidra.ready","params":{"session_id":…,"program_name":…}}`
//! - One response for each request, with exactly one of `result` and `error`.
//!   The `data` object of a bridge error can change the status, the code, the
//!   message and the target. It can also contain structured `details`.
//!
//! The decoder is strict. Unknown fields, wrong types and ambiguous messages
//! are errors. The daemon closes the bridge connection at the first message
//! that is not valid.

use crate::model::{RpcEnvelope, RpcError};
use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};

/// The only `jsonrpc` value that the decoder accepts.
const VERSION: &str = "2.0";

/// The notification that completes the bridge handshake.
const READY_METHOD: &str = "ghidra.ready";

/// A decoded message from the bridge.
#[derive(Debug)]
pub enum Incoming {
    /// The `ghidra.ready` notification. The decoder compared it with the session.
    Ready,
    /// A response to the request that has this ID.
    Response {
        /// The request ID, as a string.
        id: String,
        /// The response, which the daemon can return to the caller.
        envelope: Box<RpcEnvelope>,
    },
    /// A protocol error response from the bridge that has no request ID or a null ID.
    ProtocolError(Box<RpcEnvelope>),
    /// A valid notification. The daemon does nothing with it.
    Notification,
}

/// A JSON-RPC message, before the decoder classifies it as a notification or a response.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    /// Must be [`VERSION`].
    jsonrpc: String,
    /// Only in notifications.
    method: Option<String>,
    /// The parameters of a notification. An explicit `null` counts as a value.
    #[serde(default, deserialize_with = "present")]
    params: Option<Value>,
    /// Only in responses.
    id: Option<Value>,
    /// The result of a successful response. An explicit `null` counts as a value.
    #[serde(default, deserialize_with = "present")]
    result: Option<Value>,
    /// The error of a failed response.
    error: Option<ErrorObject>,
}

/// The parameters of `ghidra.ready`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyParams {
    /// The session for which the daemon launched the bridge. It must agree with the credential.
    session_id: String,
    /// The program that Ghidra opened. It must not be empty.
    program_name: String,
}

/// A JSON-RPC error object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorObject {
    /// The JSON-RPC error code. The decoder uses it when `data.code` is not present.
    code: i64,
    /// The error message. The decoder uses it when `data.message` is not present.
    message: String,
    /// The error details of the bridge.
    data: Option<Map<String, Value>>,
}

/// The `error.data` object of the bridge. The decoder parses it only to
/// examine it and to read the fields that change the error. The daemon sends
/// the raw object to the client without changes.
#[derive(Deserialize)]
struct ErrorData {
    /// An HTTP-style status, from 100 to 599.
    status: Option<u16>,
    /// A machine-readable code. The decoder uses it instead of the numeric JSON-RPC code.
    code: Option<String>,
    /// The decoder uses it instead of the JSON-RPC message.
    message: Option<String>,
    /// The argument or the object of the error.
    target: Option<String>,
    /// Structured details. The decoder examines only their type.
    #[allow(dead_code)]
    details: Option<Map<String, Value>>,
}

/// Deserializes a field as `Some`. A null value also becomes `Some`.
/// Then the decoder can identify a field that is not present.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// Encodes one request. If `params` is `null`, it becomes `{}`, because the
/// bridge needs an object.
///
/// # Errors
///
/// Fails if `params` is not an object and not `null`.
pub fn encode_request(id: &str, method: &str, params: Value) -> Result<String> {
    let params = match params {
        Value::Null => json!({}),
        Value::Object(_) => params,
        _ => bail!("params must be an object"),
    };
    Ok(json!({ "jsonrpc": VERSION, "id": id, "method": method, "params": params }).to_string())
}

/// Decodes one message from the bridge that authenticated as `session_id`.
///
/// JSON-RPC has no session field. For this reason, the authenticated connection is the
/// only source of the session identity, and each response is for `session_id`.
///
/// # Errors
///
/// Fails if the message is not strictly valid. Also fails if `ghidra.ready`
/// names a different session or does not name a program.
pub fn decode_incoming(text: &str, session_id: &str) -> Result<Incoming> {
    let message: Message = serde_json::from_str(text)?;
    ensure!(message.jsonrpc == VERSION, "jsonrpc must equal 2.0");
    if message.method.is_some() {
        decode_notification(message, session_id)
    } else {
        decode_response(message, session_id)
    }
}

/// Decodes a message that has a `method`.
fn decode_notification(message: Message, session_id: &str) -> Result<Incoming> {
    let method = message.method.unwrap_or_default();
    ensure!(
        !method.is_empty()
            && message.id.is_none()
            && message.result.is_none()
            && message.error.is_none(),
        "invalid notification"
    );
    let params = match message.params {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(params @ Value::Object(_)) => params,
        Some(_) => bail!("params must be an object"),
    };
    if method != READY_METHOD {
        return Ok(Incoming::Notification);
    }
    let ready = ReadyParams::deserialize(params)?;
    ensure!(
        ready.session_id == session_id && !ready.program_name.is_empty(),
        "ghidra.ready does not match the authenticated session"
    );
    Ok(Incoming::Ready)
}

/// Decodes a message without a `method`. It must be a response.
fn decode_response(message: Message, session_id: &str) -> Result<Incoming> {
    ensure!(message.params.is_none(), "response cannot contain params");
    let id = match message.id {
        Some(Value::String(id)) if !id.is_empty() => Some(id),
        Some(Value::Number(id)) if id.is_i64() || id.is_u64() => Some(id.to_string()),
        None | Some(Value::Null) if message.error.is_some() => None,
        _ => bail!("id must be a string or integer"),
    };
    let envelope = match (message.result, message.error) {
        (Some(result), None) => {
            let Some(id) = id else {
                bail!("successful response requires an id");
            };
            let mut envelope = RpcEnvelope::response(id.clone(), session_id.into(), 200);
            envelope.result = Some(result);
            return Ok(Incoming::Response {
                id,
                envelope: Box::new(envelope),
            });
        }
        (None, Some(error)) => {
            let req_id = id.as_deref().unwrap_or("");
            decode_error(req_id, session_id, error)?
        }
        _ => bail!("response requires exactly one of result or error"),
    };
    if let Some(id) = id {
        Ok(Incoming::Response {
            id,
            envelope: Box::new(envelope),
        })
    } else {
        Ok(Incoming::ProtocolError(Box::new(envelope)))
    }
}

/// Makes the envelope of a failed response. The details in `error.data` have
/// priority over the JSON-RPC code and message.
fn decode_error(id: &str, session_id: &str, error: ErrorObject) -> Result<RpcEnvelope> {
    ensure!(
        !error.message.trim().is_empty(),
        "error.message must be a non-empty string"
    );
    let raw = error.data.unwrap_or_default();
    let data = ErrorData::deserialize(Value::Object(raw.clone()))?;
    if let Some(status) = data.status {
        ensure!((100..=599).contains(&status), "invalid bridge error status");
    }
    let mut envelope = RpcEnvelope::response(
        id.to_string(),
        session_id.to_string(),
        data.status.map_or(500, i32::from),
    );
    envelope.error = Some(RpcError {
        code: data
            .code
            .filter(|code| !code.is_empty())
            .unwrap_or_else(|| error.code.to_string()),
        message: data.message.unwrap_or(error.message),
        target: data.target,
    });
    envelope.error_data = Some(Value::Object(raw));
    Ok(envelope)
}
