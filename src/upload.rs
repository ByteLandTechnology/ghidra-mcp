// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Binary uploads from remote MCP clients.
//!
//! A client that cannot share a file path with the daemon uploads a binary in two steps:
//!
//! 1. The `upload.prepare` command gives a single-use **upload credential** for
//!    a declared MD5, file name and size. It also returns a URL that is relative
//!    to the MCP endpoint. Then the URL also works behind a reverse proxy with a prefix.
//! 2. The client sends the raw bytes with `POST /upload` and the credential as a
//!    bearer token. The daemon writes the bytes to a temporary file and examines
//!    the size and the MD5. Then it saves the binary, and opens its session or
//!    uses the session again.
//!
//! The request uses the credential when it starts, before the daemon reads a
//! byte. For this reason, the client needs a new credential after an upload fails.
//! The client must use the
//! credential before [`GRANT_LIFETIME`] ends. This limit never stops an upload
//! that is in progress. The daemon compares the Host and Origin headers with
//! the addresses of its listener. This stops DNS rebinding and cross-site requests from browsers.

use crate::project::{deserialize_md5, persist_binary, validate_file_name};
use crate::state::McpState;
use anyhow::{Context, Result};
use axum::{
  body::{Body, BodyDataStream},
  extract::State,
  http::{header, uri::Authority, HeaderMap, StatusCode, Uri},
  response::{IntoResponse, Response},
  Json,
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::num::NonZeroU64;
use std::{
  collections::HashMap,
  fs,
  sync::{Arc, Mutex},
  time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The time during which an unused upload credential is valid.
const GRANT_LIFETIME: Duration = Duration::from_mins(10);

/// The maximum number of bytes that the daemon reads and discards after it refuses an upload.
const DRAIN_LIMIT: u64 = 1024 * 1024 * 1024;

/// The maximum time that the daemon reads and discards bytes after it refuses an upload.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The arguments of `upload.prepare`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareArgs {
  /// The MD5 of the binary. The upload must have this MD5.
  #[serde(deserialize_with = "deserialize_md5")]
  md5: String,
  /// The display name of the binary.
  file_name: String,
  /// The exact size of the upload in bytes.
  size: NonZeroU64,
}

/// The data that an upload credential is for.
struct UploadGrant {
  /// The MD5 that the upload must have.
  md5: String,
  /// The display name of the binary.
  file_name: String,
  /// The exact size of the upload in bytes.
  size: u64,
  /// The time after which the daemon refuses the credential.
  deadline: Instant,
}

/// Gives upload credentials and receives uploads.
pub struct UploadService {
  /// The shared daemon state.
  state: Arc<McpState>,
  /// The `host:port` forms of the listener that the Host and Origin headers can have.
  authorities: [String; 2],
  /// The daemon cancels this token when it stops. This stops the uploads that are in progress.
  cancellation: CancellationToken,
  /// The credentials available for first use, with the token as key.
  grants: Mutex<HashMap<String, UploadGrant>>,
}

impl UploadService {
  /// Makes the service and removes temporary uploads from a daemon that stopped.
  /// The caller has the daemon lock. Thus, no other daemon uses these files.
  ///
  /// # Errors
  ///
  /// Fails if the daemon cannot read or clear the temporary directory.
  pub fn new(
    state: Arc<McpState>,
    authorities: [String; 2],
    cancellation: CancellationToken,
  ) -> Result<Arc<Self>> {
    // A daemon that stops can leave temporary uploads or orphaned bridge runtime JARs.
    // The lock holder owns the private runtime directory before this cleanup starts.
    for entry in fs::read_dir(&state.paths.tmp_dir)? {
      let entry = entry?;
      let name = entry.file_name();
      let name = name.to_string_lossy();
      let is_tmp_upload = name.starts_with("upload-") && name.ends_with(".tmp");
      let is_bridge_runtime = name.starts_with("ghidra-bridge-runtime-") && name.ends_with(".jar");
      if is_tmp_upload || is_bridge_runtime {
        let kind = entry.file_type()?;
        if kind.is_file() || kind.is_symlink() {
          fs::remove_file(entry.path())?;
        }
      }
    }
    Ok(Arc::new(Self {
      state,
      authorities,
      cancellation,
      grants: Mutex::new(HashMap::new()),
    }))
  }

  /// Runs `upload.prepare`. Makes a credential and returns the upload request
  /// that the client must send.
  ///
  /// # Errors
  ///
  /// Fails during the shutdown, or for a file name that is not valid.
  pub fn prepare(&self, args: PrepareArgs) -> Result<(String, Value)> {
    if self.state.is_shutting_down() {
      return Err(crate::error::DomainError::ShuttingDown.into());
    }
    let PrepareArgs {
      md5,
      file_name,
      size,
    } = args;
    validate_file_name(&file_name)?;
    let size = size.get();
    let now = Instant::now();
    let expires_at = SystemTime::now()
      .duration_since(UNIX_EPOCH)?
      .checked_add(GRANT_LIFETIME)
      .context("upload expiration is out of range")?
      .as_secs();
    let token = Uuid::new_v4().simple().to_string();
    let mut grants = self.grants.lock().expect("upload grants lock poisoned");
    grants.retain(|_, grant| grant.deadline > now);
    grants.insert(
      token.clone(),
      UploadGrant {
        md5,
        file_name,
        size,
        deadline: now + GRANT_LIFETIME,
      },
    );
    Ok((
      "Upload the raw binary to the returned endpoint".to_string(),
      json!({
          "method": "POST",
          "url": "upload",
          "headers": {
              "Authorization": format!("Bearer {token}"),
              "Content-Type": "application/octet-stream"
          },
          "expiresAt": expires_at
      }),
    ))
  }

  /// Examines the Host and Origin of the request, and then uses its credential.
  fn authorize(&self, uri: &Uri, headers: &HeaderMap) -> UploadResult<UploadGrant> {
    self.validate_authority(uri, headers)?;
    let credential = crate::bridge::bearer_token(headers)
      .ok_or_else(|| UploadError::unauthorized("a valid upload credential is required"))?;
    let now = Instant::now();
    let mut grants = self.grants.lock().expect("upload grants lock poisoned");
    // Use the credential before the daemon reads headers or bytes. A failed upload
    // needs a new credential. The expiry only decides if a request can start.
    let grant = grants.remove(&credential);
    grants.retain(|_, grant| grant.deadline > now);
    grant
      .filter(|grant| grant.deadline > now)
      .ok_or_else(|| UploadError::unauthorized("upload credential has expired or was used"))
  }

  /// Accepts only the Host of the listener. Accepts no Origin, or an `http`
  /// Origin of the listener. This stops DNS rebinding and cross-site browser requests.
  fn validate_authority(&self, uri: &Uri, headers: &HeaderMap) -> UploadResult<()> {
    let host = if headers.contains_key(header::HOST) {
      single_header(headers, header::HOST)
    } else {
      // HTTP/2 uses :authority, and a request can have no separate Host header.
      uri.authority().map(Authority::as_str)
    };
    require(
      host.is_some_and(|host| self.authority_allowed(host)),
      StatusCode::FORBIDDEN,
      "upload Host is not allowed",
    )?;
    if headers.contains_key(header::ORIGIN) {
      let origin_allowed = single_header(headers, header::ORIGIN)
        .and_then(|origin| origin.parse::<Uri>().ok())
        .is_some_and(|origin| {
          origin
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
            && origin
              .authority()
              .is_some_and(|authority| self.authority_allowed(authority.as_str()))
            && origin.path() == "/"
            && origin.query().is_none()
        });
      require(
        origin_allowed,
        StatusCode::FORBIDDEN,
        "upload Origin is not allowed",
      )?;
    }
    Ok(())
  }

  /// Returns `true` if `value` is one of the `host:port` forms of the listener.
  fn authority_allowed(&self, value: &str) -> bool {
    let Ok(authority) = value.parse::<Authority>() else {
      return false;
    };
    self.authorities.iter().any(|allowed| {
      let allowed: Authority = allowed.parse().expect("bound listener authority is valid");
      authority.host().eq_ignore_ascii_case(allowed.host())
        && authority.port_u16() == allowed.port_u16()
    })
  }

  /// Receives one upload. It examines the request, writes the bytes to a
  /// temporary file, and calculates their MD5. Then it saves the binary and
  /// opens its session. Returns 200 when the session is ready, and 202 while it starts.
  async fn receive(
    &self,
    uri: Uri,
    headers: HeaderMap,
    stream: &mut BodyDataStream,
  ) -> UploadResult<(StatusCode, Value)> {
    let grant = self.authorize(&uri, &headers)?;
    let octet_stream = single_header(&headers, header::CONTENT_TYPE)
      .and_then(|value| value.split(';').next())
      .is_some_and(|value| {
        value
          .trim()
          .eq_ignore_ascii_case("application/octet-stream")
      });
    require(
      octet_stream,
      StatusCode::UNSUPPORTED_MEDIA_TYPE,
      "upload Content-Type must be application/octet-stream",
    )?;
    let declared_size =
      single_header(&headers, header::CONTENT_LENGTH).and_then(|size| size.parse::<u64>().ok());
    require(
      !headers.contains_key(header::CONTENT_LENGTH) || declared_size == Some(grant.size),
      StatusCode::BAD_REQUEST,
      "upload Content-Length does not match the prepared size",
    )?;

    // The daemon makes the file before it starts an asynchronous task.
    // Thus, cancellation cannot leave a file from a detached file system task.
    // The drop of `temporary` deletes the file.
    let temporary = tempfile::Builder::new()
      .prefix("upload-")
      .suffix(".tmp")
      .tempfile_in(&self.state.paths.tmp_dir)
      .map_err(internal("cannot create temporary upload"))?;
    let file = temporary
      .as_file()
      .try_clone()
      .map_err(internal("cannot create temporary upload"))?;
    let mut file = tokio::fs::File::from_std(file);
    let mut digest = md5::Context::new();
    let mut size = 0u64;
    while let Some(chunk) = stream.next().await {
      let chunk = chunk.map_err(reject(
        StatusCode::BAD_REQUEST,
        "upload stream was interrupted",
      ))?;
      size = size.saturating_add(chunk.len() as u64);
      require(
        size <= grant.size,
        StatusCode::PAYLOAD_TOO_LARGE,
        "upload exceeds the prepared size",
      )?;
      digest.consume(&chunk);
      file
        .write_all(&chunk)
        .await
        .map_err(internal("cannot write temporary upload"))?;
    }
    require(
      size == grant.size,
      StatusCode::BAD_REQUEST,
      "upload byte count does not match the prepared size",
    )?;
    require(
      format!("{:x}", digest.compute()) == grant.md5,
      StatusCode::UNPROCESSABLE_ENTITY,
      "upload MD5 does not match the prepared digest",
    )?;
    file
      .sync_all()
      .await
      .map_err(internal("cannot save temporary upload"))?;
    let paths = self.state.paths.clone();
    let temp_path = temporary.path().to_path_buf();
    let md5 = grant.md5.clone();
    let file_name = grant.file_name.clone();
    tokio::task::spawn_blocking(move || persist_binary(&paths, &temp_path, &md5, &file_name))
      .await
      .map_err(internal("binary persistence task panicked"))?
      .map_err(internal("cannot persist uploaded binary"))?;
    let (_, result) = crate::session::open(&self.state, grant.md5, None, None)
      .await
      .map_err(internal(
        "binary was saved, but the session could not be opened; retry session.open with its MD5",
      ))?;
    let status = match result.pointer("/session/status").and_then(Value::as_str) {
      Some("ready") => StatusCode::OK,
      Some("launching" | "starting") => StatusCode::ACCEPTED,
      _ => {
        return Err(UploadError::new(
          StatusCode::INTERNAL_SERVER_ERROR,
          "binary was saved, but the session is unavailable; retry session.open with its MD5",
        ))
      }
    };
    Ok((status, result))
  }
}

/// The handler of `POST /upload`.
pub async fn upload(
  State(service): State<Arc<UploadService>>,
  uri: Uri,
  headers: HeaderMap,
  body: Body,
) -> Response {
  let mut stream = body.into_data_stream();
  let result = tokio::select! {
      biased;
      () = service.cancellation.cancelled() => {
        Err(UploadError::new(StatusCode::SERVICE_UNAVAILABLE, "daemon is shutting down"))
      }
      result = service.receive(uri, headers, &mut stream) => result,
  };
  match result {
    Ok((status, body)) => (status, Json(body)).into_response(),
    Err(error) => {
      tokio::select! {
          () = service.cancellation.cancelled() => {}
          () = drain(&mut stream) => {}
      }
      (error.status, Json(json!({"error": error.message}))).into_response()
    }
  }
}

/// Reads and discards the other bytes of a refused upload.
///
/// Many clients send all of the body before they read the response. Some
/// bytes can arrive after the daemon closes the connection. Then the operating
/// system resets the connection, and the client does not get the error
/// response. The limits stop a client that sends too much data.
async fn drain(stream: &mut BodyDataStream) {
  let discard = async {
    let mut read = 0u64;
    while let Some(Ok(chunk)) = stream.next().await {
      read += chunk.len() as u64;
      if read > DRAIN_LIMIT {
        break;
      }
    }
  };
  let _ = tokio::time::timeout(DRAIN_TIMEOUT, discard).await;
}

/// Returns a header that occurs exactly once. A repeated header
/// has the same effect as no header.
fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
  let mut values = headers.get_all(name).iter();
  let value = values.next()?.to_str().ok()?;
  values.next().is_none().then_some(value)
}

/// The result of the upload handler.
type UploadResult<T> = std::result::Result<T, UploadError>;

/// An upload failure: an HTTP status and a fixed message.
struct UploadError {
  /// The status of the response.
  status: StatusCode,
  /// The `error` text of the response.
  message: &'static str,
}

/// Changes an error into a fixed error for the client, for `map_err`. The
/// client never sees the internal cause, for example a file path.
fn reject<E>(status: StatusCode, message: &'static str) -> impl FnOnce(E) -> UploadError {
  move |_| UploadError::new(status, message)
}

/// The same as [`reject`], with the status 500.
fn internal<E>(message: &'static str) -> impl FnOnce(E) -> UploadError {
  reject(StatusCode::INTERNAL_SERVER_ERROR, message)
}

/// Fails with `status` and `message` if `condition` is `false`.
fn require(condition: bool, status: StatusCode, message: &'static str) -> UploadResult<()> {
  if condition {
    Ok(())
  } else {
    Err(UploadError::new(status, message))
  }
}

impl UploadError {
  /// Makes an error with `status` and `message`.
  fn new(status: StatusCode, message: &'static str) -> Self {
    Self { status, message }
  }

  /// Makes a 401 error.
  fn unauthorized(message: &'static str) -> Self {
    Self::new(StatusCode::UNAUTHORIZED, message)
  }
}
