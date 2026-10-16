// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Typed domain errors and their JSON-RPC protocol codes.
//!
//! The [`DomainError`] enum shows all failure modes in the daemon, the state
//! machine, and bridge interactions. These errors map to standard JSON-RPC
//! error codes and structured MCP error envelopes.

use crate::model::RpcError;
use serde_json::{json, Value};

/// Standard JSON-RPC 2.0 error code for invalid method parameters.
pub const RPC_CODE_INVALID_ARGUMENT: i32 = -32602;

/// Implementation-defined error code for session lock timeouts.
pub const RPC_CODE_SESSION_LOCK_TIMEOUT: i32 = -32001;

/// Implementation-defined error code for absent binaries, sessions, or jobs.
pub const RPC_CODE_MISSING_TARGET: i32 = -32002;

/// Implementation-defined error code for disconnected sessions or daemon shutdown.
pub const RPC_CODE_DISCONNECTED: i32 = -32000;

/// Standard JSON-RPC 2.0 error code for internal server errors.
pub const RPC_CODE_INTERNAL_ERROR: i32 = -32603;

/// Domain error variants for all failure modes of `ghidra-mcp`.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A tool or command argument is invalid or absent.
    #[error("invalid argument `{param}`: {reason}")]
    InvalidArgument {
        /// Name of the parameter or field that failed validation.
        param: String,
        /// Human-readable explanation of why the parameter is invalid.
        reason: String,
    },

    /// Timeout for the per-session request serialization lock.
    #[error("agent did not respond in time (waiting for session request lock for `{md5}`)")]
    SessionLockTimeout {
        /// MD5 hash of the session binary.
        md5: String,
        /// Configured timeout duration in seconds.
        timeout_seconds: u64,
    },

    /// The requested target (binary, session, or job) does not exist or is not available.
    #[error("target `{target}` is not available: {reason}")]
    MissingTarget {
        /// Identifier or name of the target that the daemon did not find.
        target: String,
        /// Explanation of why the target is unavailable.
        reason: String,
    },

    /// The session has no active bridge agent connection.
    #[error("session has no active agent connection: {md5}")]
    Disconnected {
        /// MD5 hash of the disconnected session.
        md5: String,
    },

    /// The bridge agent did not respond within the configured RPC timeout.
    #[error("agent did not respond in time")]
    AgentTimeout {
        /// MD5 hash of the session that timed out.
        md5: String,
        /// Optional timeout duration in seconds.
        timeout_seconds: Option<u64>,
    },

    /// The session already has an in-flight request with no response.
    #[error("session already has a request in flight: {md5}")]
    RequestInFlight {
        /// MD5 hash of the session with the active request.
        md5: String,
    },

    /// The daemon started its shutdown and refuses new requests.
    #[error("daemon is shutting down")]
    ShuttingDown,

    /// A Ghidra database or program transaction failed, or Ghidra reverted it.
    #[error("transaction failed: {reason}")]
    TransactionFailed {
        /// Cause of the transaction abort or database error.
        reason: String,
    },

    /// The Java bridge reported an internal execution error (HTTP 500).
    #[error("bridge internal error: {reason}")]
    BridgeInternal {
        /// Error code string from the bridge.
        code: String,
        /// Error message from the bridge.
        reason: String,
    },

    /// An unclassified internal system or runtime error occurred.
    #[error("internal error: {message}")]
    Internal {
        /// Description of the internal failure.
        message: String,
    },
}

impl DomainError {
    /// Classifies a bridge error by its status and code.
    #[must_use]
    pub fn from_bridge(status: Option<i32>, error: &RpcError) -> Self {
        if error.code.eq_ignore_ascii_case("bridge_disconnected")
            || error.code.eq_ignore_ascii_case("disconnected")
            || (status == Some(502) && error.message.contains("disconnect"))
        {
            return Self::Disconnected {
                md5: error
                    .target
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            };
        }
        match (status, error.code.as_str()) {
            (Some(500..=599), "transaction_failed") => Self::transaction_failed(&error.message),
            (Some(500..=599), _) => Self::BridgeInternal {
                code: error.code.clone(),
                reason: error.message.clone(),
            },
            (Some(400), _) | (_, "invalid_request") => {
                Self::invalid_argument(error.target.as_deref().unwrap_or("request"), &error.message)
            }
            (Some(404), _) | (_, "resource_not_found") => Self::missing_target(
                error.target.as_deref().unwrap_or("resource"),
                &error.message,
            ),
            _ => Self::Internal {
                message: error.message.clone(),
            },
        }
    }

    /// Keeps a typed cause. Gives unexpected failures a safe public message.
    #[must_use]
    pub fn from_error(error: &anyhow::Error) -> Self {
        if let Some(domain) = error.downcast_ref::<Self>() {
            return domain.clone();
        }
        for cause in error.chain() {
            if let Some(service_err) = cause.downcast_ref::<rmcp::service::ServiceError>() {
                if matches!(
                    service_err,
                    rmcp::service::ServiceError::TransportClosed
                        | rmcp::service::ServiceError::TransportSend(_)
                ) {
                    return Self::Disconnected {
                        md5: "daemon".to_string(),
                    };
                }
            }
            if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
                if matches!(
                    io_err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::BrokenPipe
                ) {
                    return Self::Disconnected {
                        md5: "daemon".to_string(),
                    };
                }
            }
        }
        Self::Internal {
            message: "request failed; inspect daemon.log".to_string(),
        }
    }

    /// Returns the related JSON-RPC numeric error code.
    #[must_use]
    pub fn rpc_code(&self) -> i32 {
        match self {
            Self::InvalidArgument { .. } => RPC_CODE_INVALID_ARGUMENT,
            Self::SessionLockTimeout { .. }
            | Self::AgentTimeout { .. }
            | Self::RequestInFlight { .. } => RPC_CODE_SESSION_LOCK_TIMEOUT,
            Self::MissingTarget { .. } => RPC_CODE_MISSING_TARGET,
            Self::Disconnected { .. } | Self::ShuttingDown => RPC_CODE_DISCONNECTED,
            Self::TransactionFailed { .. }
            | Self::BridgeInternal { .. }
            | Self::Internal { .. } => RPC_CODE_INTERNAL_ERROR,
        }
    }

    /// Returns the machine-readable error type identifier.
    #[must_use]
    pub fn machine_code(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => "invalid_argument",
            Self::SessionLockTimeout { .. } => "session_lock_timeout",
            Self::MissingTarget { .. } => "missing_target",
            Self::Disconnected { .. } => "disconnected",
            Self::AgentTimeout { .. } => "agent_timeout",
            Self::RequestInFlight { .. } => "request_in_flight",
            Self::ShuttingDown => "shutting_down",
            Self::TransactionFailed { .. } => "transaction_failed",
            Self::BridgeInternal { .. } => "bridge_internal",
            Self::Internal { .. } => "internal_error",
        }
    }

    /// Returns structured machine-readable contextual details for `error.data.details`.
    #[must_use]
    pub fn details(&self) -> Option<Value> {
        match self {
            Self::InvalidArgument { param, reason } => {
                Some(json!({ "param": param, "reason": reason }))
            }
            Self::SessionLockTimeout {
                md5,
                timeout_seconds,
            } => Some(json!({ "md5": md5, "timeout_seconds": timeout_seconds })),
            Self::MissingTarget { target, reason } => {
                Some(json!({ "target": target, "reason": reason }))
            }
            Self::Disconnected { md5 } | Self::RequestInFlight { md5 } => {
                Some(json!({ "md5": md5 }))
            }
            Self::AgentTimeout {
                md5,
                timeout_seconds,
            } => match timeout_seconds {
                Some(secs) => Some(json!({ "md5": md5, "timeout_seconds": secs })),
                None => Some(json!({ "md5": md5 })),
            },
            Self::ShuttingDown => None,
            Self::TransactionFailed { reason } => Some(json!({ "reason": reason })),
            Self::BridgeInternal { code, reason } => {
                Some(json!({ "code": code, "reason": reason }))
            }
            Self::Internal { message } => Some(json!({ "message": message })),
        }
    }

    /// Makes the standard MCP tool JSON error response envelope.
    #[must_use]
    pub fn to_envelope(&self) -> Value {
        let mut data = serde_json::Map::new();
        data.insert("type".to_string(), json!(self.machine_code()));
        if let Some(details) = self.details() {
            data.insert("details".to_string(), details);
        }

        json!({
          "response": {
            "status": "error",
            "error": {
              "code": self.rpc_code(),
              "message": self.to_string(),
              "data": Value::Object(data)
            }
          }
        })
    }

    /// Helper constructor for [`DomainError::InvalidArgument`].
    #[must_use]
    pub fn invalid_argument(param: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidArgument {
            param: param.into(),
            reason: reason.into(),
        }
    }

    /// Helper constructor for [`DomainError::SessionLockTimeout`].
    #[must_use]
    pub fn session_lock_timeout(md5: impl Into<String>, timeout_seconds: u64) -> Self {
        Self::SessionLockTimeout {
            md5: md5.into(),
            timeout_seconds,
        }
    }

    /// Helper constructor for [`DomainError::MissingTarget`].
    #[must_use]
    pub fn missing_target(target: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::MissingTarget {
            target: target.into(),
            reason: reason.into(),
        }
    }

    /// Helper constructor for [`DomainError::Disconnected`].
    #[must_use]
    pub fn disconnected(md5: impl Into<String>) -> Self {
        Self::Disconnected { md5: md5.into() }
    }

    /// Helper constructor for [`DomainError::TransactionFailed`].
    #[must_use]
    pub fn transaction_failed(reason: impl Into<String>) -> Self {
        Self::TransactionFailed {
            reason: reason.into(),
        }
    }
}
