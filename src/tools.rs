// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The public MCP tool `ghidra`: its local commands and its dispatch.
//!
//! The tool takes a `command` argument and the arguments of that command.
//! There are two types of commands:
//!
//! - The [`LOCAL_COMMANDS`]. This module implements them.
//! - The bridge methods of the bridge contract. The daemon sends them to the
//!   bridge of the session.
//!
//! [`dispatch`] validates the arguments against the schema of the command
//! (see [`catalog`]) before it runs the command.
//!
//! Each command returns a short summary text and a structured JSON result.
//! Bridge methods return `{"response": …}`. To add a local command, add one
//! entry to the table.

mod catalog {
  //! The command catalog: the local commands together with the bridge contract,
  //! the validation of arguments against the catalog, and `help`.

  use super::LOCAL_COMMANDS;
  use crate::error::DomainError;
  use anyhow::Result;
  use serde::Deserialize;
  use serde_json::{json, Value};
  use std::sync::LazyLock;

  /// The command catalog. The daemon makes it one time, at its first use.
  static COMMANDS: LazyLock<Vec<Command>> = LazyLock::new(build_commands);

  /// A catalog entry: a local command, a bridge method, or the two together.
  struct Command {
    /// The full name, for example `function.get`.
    name: String,
    /// The description that `help` shows.
    description: String,
    /// The JSON Schema of the arguments.
    input_schema: Value,
    /// `true` if the command can change the Ghidra state or the session state.
    mutation: bool,
  }

  impl Command {
    /// Returns the part of the name before the first `.`.
    fn category(&self) -> &str {
      self
        .name
        .split_once('.')
        .map_or(&self.name, |(category, _)| category)
    }
  }

  /// Returns the arguments that `help` and the `ghidra` tool have in common.
  pub(super) fn help_properties() -> Value {
    json!({
        "category": { "type": "string" },
        "commandName": { "type": "string" }
    })
  }

  /// Returns the schema of an `md5` argument.
  pub(super) fn md5_schema() -> Value {
    json!({ "type": "string", "pattern": "^[0-9a-fA-F]{32}$" })
  }

  /// Returns the MCP tool definitions: one tool, `ghidra`.
  pub fn tool_definitions() -> Vec<Value> {
    let mut properties = help_properties();
    properties["command"] = json!({ "type": "string" });
    vec![json!({
        "name": "ghidra",
        "description": concat!(
            "Run a Ghidra MCP command. Start with command=help. Pass category to list commands. ",
            "Pass commandName to inspect one command's parameters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": ["command"]
        }
    })]
  }

  /// Makes the catalog: the local commands first, then the bridge methods in
  /// name sequence. The schema of a bridge method gets a required `md5`. A
  /// local command with the same name gets the schema of the method, and keeps
  /// its own other arguments.
  fn build_commands() -> Vec<Command> {
    let mut commands: Vec<Command> = LOCAL_COMMANDS
      .iter()
      .map(|local| Command {
        name: local.name.to_string(),
        description: local.description.to_string(),
        input_schema: (local.schema)(),
        mutation: local.mutation,
      })
      .collect();

    for (name, method) in crate::bridge::methods() {
      let mut schema = method["input_schema"].clone();
      schema["properties"]["md5"] = md5_schema();
      let mut required = schema["required"].as_array().cloned().unwrap_or_default();
      required.insert(0, json!("md5"));
      schema["required"] = json!(required);
      let mutation = !method["effects"]["read_only"]
        .as_bool()
        .expect("bridge read_only effect");
      if let Some(existing) = commands.iter_mut().find(|command| command.name == *name) {
        // Session and analysis commands add lifecycle behavior to a bridge operation.
        let local_properties = existing.input_schema["properties"]
          .as_object()
          .cloned()
          .unwrap_or_default();
        let properties = schema["properties"]
          .as_object_mut()
          .expect("schema properties");
        for (field, local_schema) in local_properties {
          properties.entry(field).or_insert(local_schema);
        }
        existing.input_schema = schema;
        existing.mutation |= mutation;
      } else {
        commands.push(Command {
          name: name.clone(),
          description: method["description"]
            .as_str()
            .expect("bridge method description")
            .to_string(),
          input_schema: schema,
          mutation,
        });
      }
    }
    commands
  }

  /// Examines the required and unexpected arguments against the schema of a command.
  pub(super) fn validate_args(command: &str, args: &Value) -> Result<()> {
    let Some(schema) = COMMANDS
      .iter()
      .find(|definition| definition.name == command)
      .map(|definition| &definition.input_schema)
    else {
      return Ok(());
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
      return Ok(());
    };
    let object = args.as_object().ok_or_else(|| {
      DomainError::invalid_argument(
        "arguments",
        format!("command `{command}` requires an argument object"),
      )
    })?;
    let required = schema["required"].as_array().into_iter().flatten();
    for field in required.filter_map(Value::as_str) {
      if !object.contains_key(field) {
        return Err(
          DomainError::invalid_argument(
            field,
            format!("command `{command}` requires argument `{field}`"),
          )
          .into(),
        );
      }
    }
    if schema.get("additionalProperties") == Some(&json!(false)) {
      if let Some(key) = object.keys().find(|key| !properties.contains_key(*key)) {
        return Err(
          DomainError::invalid_argument(
            key,
            format!("command `{command}` does not accept argument `{key}`"),
          )
          .into(),
        );
      }
    }
    Ok(())
  }

  /// The arguments of `help`.
  #[derive(Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub(super) struct HelpArgs {
    /// The category whose commands to list.
    category: Option<String>,
    /// The command to describe.
    command_name: Option<String>,
  }

  /// Lists the categories, the commands of one category, or the schema of one command.
  pub(super) fn help(args: &HelpArgs) -> Result<super::Output> {
    match (args.category.as_deref(), args.command_name.as_deref()) {
      (Some(_), Some(_)) => Err(
        DomainError::invalid_argument(
          "category/commandName",
          "help accepts either category or commandName, not both",
        )
        .into(),
      ),
      (None, Some(command_name)) => {
        let command = COMMANDS
          .iter()
          .find(|command| command.name == command_name)
          .ok_or_else(|| {
            DomainError::missing_target(command_name, format!("unknown command: {command_name}"))
          })?;
        Ok((
          format!("Help for {command_name}"),
          json!({
              "command": {
                  "name": command.name,
                  "category": command.category(),
                  "description": command.description,
                  "mutation": command.mutation,
                  "inputSchema": command.input_schema
              }
          }),
        ))
      }
      (Some(category), None) => {
        let matches: Vec<Value> = COMMANDS
          .iter()
          .filter(|command| command.category() == category)
          .map(|command| {
            json!({
                "name": command.name,
                "description": command.description,
                "mutation": command.mutation
            })
          })
          .collect();
        if matches.is_empty() {
          return Err(
            DomainError::missing_target(category, format!("unknown command category: {category}"))
              .into(),
          );
        }
        Ok((
          format!("Found {} command(s) in {category}", matches.len()),
          json!({ "category": category, "commands": matches }),
        ))
      }
      (None, None) => {
        let mut categories: Vec<(&str, usize)> = Vec::new();
        for command in COMMANDS.iter() {
          match categories
            .iter_mut()
            .find(|(name, _)| *name == command.category())
          {
            Some((_, count)) => *count += 1,
            None => categories.push((command.category(), 1)),
          }
        }
        let categories: Vec<Value> = categories
          .into_iter()
          .map(|(name, count)| json!({ "name": name, "commandCount": count }))
          .collect();
        Ok((
          format!("Found {} command categories", categories.len()),
          json!({ "categories": categories }),
        ))
      }
    }
  }
}

pub use catalog::tool_definitions;

use crate::error::DomainError;
use crate::model::{JobStatus, SessionRecord};
use crate::project::{deserialize_md5, deserialize_optional_md5};
use crate::state::McpState;
use crate::upload::UploadService;
use crate::{analysis, session};
use anyhow::Result;
use futures::future::BoxFuture;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// The objects that the commands use.
pub struct Daemon {
  /// The shared daemon state.
  pub state: Arc<McpState>,
  /// The upload credentials, for `upload.prepare`.
  pub uploads: Arc<UploadService>,
}

/// The summary text and the structured result of a command.
type Output = (String, Value);

/// Runs a local command with its arguments, without `command`.
type Handler = for<'a> fn(&'a Daemon, Value) -> BoxFuture<'a, Result<Output>>;

/// A command that the daemon runs, not the bridge. A local command with the
/// name of a bridge method adds its arguments to the schema of that method.
struct LocalCommand {
  /// The command name, `<category>.<action>`.
  name: &'static str,
  /// The description that `help` shows.
  description: &'static str,
  /// The JSON Schema of the arguments, without `command`.
  schema: fn() -> Value,
  /// `true` if the command can change the Ghidra state or the session state.
  mutation: bool,
  /// Runs the command.
  run: Handler,
}

/// All local commands, in the sequence of `help`.
const LOCAL_COMMANDS: &[LocalCommand] = &[
  LocalCommand {
    name: "help",
    description: concat!(
      "List command categories. List the commands in one category. Inspect one command's ",
      "parameters. Pass no arguments to list categories."
    ),
    schema: || {
      json!({
          "type": "object",
          "properties": catalog::help_properties(),
          "additionalProperties": false
      })
    },
    mutation: false,
    run: |_, args| Box::pin(async move { catalog::help(&parse("help", &args)?) }),
  },
  LocalCommand {
    name: "session.open",
    description: concat!(
      "Open or reuse a binary session without auto-analysis. Pass md5 to load an active ",
      "or saved project, or path to import a daemon-local file. Returns at once by ",
      "default. Set wait=true to wait until ready. Upload remote files with upload.prepare."
    ),
    schema: || {
      json!({
          "type": "object",
          "properties": {
              "path": { "type": "string" },
              "md5": catalog::md5_schema(),
              "wait": { "type": "boolean", "default": false },
              "timeoutMs": { "type": "integer", "minimum": 1 }
          },
          "oneOf": [{ "required": ["path"] }, { "required": ["md5"] }],
          "additionalProperties": false
      })
    },
    mutation: true,
    run: |daemon, args| Box::pin(open_session(daemon, args)),
  },
  LocalCommand {
    name: "analysis.start",
    description: concat!(
      "Start auto-analysis for a current ready session. Returns at once by default. ",
      "Set wait=true to block until analysis completes."
    ),
    schema: || {
      json!({
          "type": "object",
          "properties": {
              "md5": catalog::md5_schema(),
              "analyzers": {
                  "type": "array",
                  "items": { "type": "string" },
                  "minItems": 1
              },
              "wait": { "type": "boolean", "default": false },
              "timeoutMs": { "type": "integer", "minimum": 1 }
          },
          "required": ["md5"],
          "additionalProperties": false
      })
    },
    mutation: true,
    run: |daemon, args| Box::pin(start_analysis(daemon, args)),
  },
  LocalCommand {
    name: "session.list",
    description: concat!(
      "List session summaries by MD5 without exposing binary paths. You do not need to ",
      "list sessions before you open one."
    ),
    schema: || {
      json!({
          "type": "object",
          "properties": {},
          "additionalProperties": false
      })
    },
    mutation: false,
    run: |daemon, _| {
      Box::pin(async move {
        let sessions: Vec<Value> = daemon
          .state
          .sessions()
          .iter()
          .map(SessionRecord::summary)
          .collect();
        Ok((
          format!("Found {} session(s)", sessions.len()),
          json!({ "sessions": sessions }),
        ))
      })
    },
  },
  LocalCommand {
    name: "session.get",
    description: "Get one session summary by MD5.",
    schema: || {
      json!({
          "type": "object",
          "properties": { "md5": catalog::md5_schema() },
          "required": ["md5"],
          "additionalProperties": false
      })
    },
    mutation: false,
    run: |daemon, args| {
      Box::pin(async move {
        let SessionArgs { md5 } = parse("session.get", &args)?;
        let session = daemon.state.session(&md5)?;
        Ok((
          format!("Fetched session {md5}"),
          json!({ "session": session.summary() }),
        ))
      })
    },
  },
  LocalCommand {
    name: "upload.prepare",
    description: concat!(
      "Prepare a single-use HTTP upload for a remote binary. Returns a POST URL relative to ",
      "the MCP URL, headers, and an expiration time. Stream raw bytes to that endpoint. A ",
      "valid upload opens or reuses the MD5 session."
    ),
    schema: || {
      json!({
          "type": "object",
          "properties": {
              "md5": catalog::md5_schema(),
              "fileName": { "type": "string", "minLength": 1 },
              "size": { "type": "integer", "minimum": 1 }
          },
          "required": ["md5", "fileName", "size"],
          "additionalProperties": false
      })
    },
    mutation: true,
    run: |daemon, args| {
      Box::pin(async move { daemon.uploads.prepare(parse("upload.prepare", &args)?) })
    },
  },
  LocalCommand {
    name: "session.close",
    description: "Close an active session.",
    schema: || {
      json!({
          "type": "object",
          "properties": {
              "md5": catalog::md5_schema(),
              "force": { "type": "boolean", "default": false }
          },
          "required": ["md5"],
          "additionalProperties": false
      })
    },
    mutation: true,
    run: |daemon, args| {
      Box::pin(async move {
        let CloseArgs { md5, force } = parse("session.close", &args)?;
        session::close(&daemon.state, &md5, force).await?;
        let session = daemon.state.session(&md5)?;
        Ok((
          format!("Closed session {md5}"),
          json!({ "session": session.summary() }),
        ))
      })
    },
  },
  LocalCommand {
    name: "job.get",
    description: "Get one background job by ID.",
    schema: || {
      json!({
          "type": "object",
          "properties": { "jobId": { "type": "string" } },
          "required": ["jobId"],
          "additionalProperties": false
      })
    },
    mutation: false,
    run: |daemon, args| {
      Box::pin(async move {
        let JobArgs { job_id, .. } = parse("job.get", &args)?;
        let job = daemon.state.job(&job_id)?;
        Ok((format!("Fetched job {job_id}"), json!({ "job": job })))
      })
    },
  },
  LocalCommand {
    name: "job.wait",
    description: "Wait for a background job to finish.",
    schema: || {
      json!({
          "type": "object",
          "properties": {
              "jobId": { "type": "string" },
              "timeoutMs": { "type": "integer", "minimum": 1 }
          },
          "required": ["jobId"],
          "additionalProperties": false
      })
    },
    mutation: false,
    run: |daemon, args| {
      Box::pin(async move {
        let JobArgs { job_id, timeout_ms } = parse("job.wait", &args)?;
        let timeout = millis_or(timeout_ms, daemon.state.config.launch_timeout());
        let job = daemon.state.await_job(&job_id, Some(timeout)).await?;
        Ok((format!("Job {job_id} finished"), json!({ "job": job })))
      })
    },
  },
];

/// Runs one `ghidra` command.
pub async fn dispatch(daemon: &Daemon, mut args: Value) -> Result<Output> {
  let command = args
    .get("command")
    .and_then(Value::as_str)
    .ok_or_else(|| DomainError::invalid_argument("command", "ghidra requires a string command"))?
    .to_string();
  if let Some(object) = args.as_object_mut() {
    object.remove("command");
  }
  catalog::validate_args(&command, &args)?;
  if let Some(local) = LOCAL_COMMANDS.iter().find(|local| local.name == command) {
    return (local.run)(daemon, args).await;
  }
  if crate::bridge::methods().contains_key(&command) {
    let BridgeArgs { md5, params } = parse(&command, &args)?;
    let response = session::call(&daemon.state, &md5, &command, Value::Object(params)).await?;
    return Ok((
      format!("{command} completed"),
      json!({ "response": response }),
    ));
  }
  Err(DomainError::missing_target(command.clone(), format!("unknown command: {command}")).into())
}

/// Deserializes the arguments of a command.
///
/// # Errors
///
/// Fails with the command name and the serde description of the problem.
fn parse<T: DeserializeOwned>(command: &str, args: &Value) -> Result<T> {
  // Put the cause in the message. The client sees tool errors without their chain.
  T::deserialize(args).map_err(|error| {
    DomainError::invalid_argument(
      command,
      format!("invalid arguments for `{command}`: {error}"),
    )
    .into()
  })
}

/// Returns the `timeoutMs` argument, or `default` if it has no value.
fn millis_or(millis: Option<u64>, default: Duration) -> Duration {
  millis.map_or(default, Duration::from_millis)
}

/// The arguments of `session.open`: exactly one of `path` and `md5`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenArgs {
  /// A file on the daemon host.
  path: Option<String>,
  /// A binary that the daemon saved or runs.
  #[serde(default, deserialize_with = "deserialize_optional_md5")]
  md5: Option<String>,
  /// Wait until the session is ready.
  #[serde(default)]
  wait: bool,
  /// The maximum wait, instead of the launch timeout.
  timeout_ms: Option<u64>,
}

/// The arguments of `analysis.start`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisArgs {
  /// The session to analyze.
  #[serde(deserialize_with = "deserialize_md5")]
  md5: String,
  /// Wait until the analysis ends.
  #[serde(default)]
  wait: bool,
  /// The maximum wait, instead of the import timeout.
  timeout_ms: Option<u64>,
  /// The other arguments. The daemon sends them to `analysis.start` of the bridge.
  #[serde(flatten)]
  params: Map<String, Value>,
}

/// The arguments of `session.get`.
#[derive(Deserialize)]
struct SessionArgs {
  /// The session.
  #[serde(deserialize_with = "deserialize_md5")]
  md5: String,
}

/// The arguments of `session.close`.
#[derive(Deserialize)]
struct CloseArgs {
  /// The session.
  #[serde(deserialize_with = "deserialize_md5")]
  md5: String,
  /// Kill the process. Do not tell the bridge to save and stop.
  #[serde(default)]
  force: bool,
}

/// The arguments of `job.get` and `job.wait`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobArgs {
  /// The job.
  job_id: String,
  /// The maximum wait of `job.wait`, instead of the launch timeout.
  timeout_ms: Option<u64>,
}

/// The arguments of a bridge method.
#[derive(Deserialize)]
struct BridgeArgs {
  /// The session that gets the request.
  #[serde(deserialize_with = "deserialize_md5")]
  md5: String,
  /// All other arguments. They are the parameters of the bridge method.
  #[serde(flatten)]
  params: Map<String, Value>,
}

/// Runs `session.open`: imports a file on the daemon host, or opens a saved binary.
async fn open_session(daemon: &Daemon, args: Value) -> Result<Output> {
  let args: OpenArgs = parse("session.open", &args)?;
  let state = &daemon.state;
  let wait = args
    .wait
    .then(|| millis_or(args.timeout_ms, state.config.launch_timeout()));
  match (args.path, args.md5) {
    (Some(path), None) => {
      let raw = PathBuf::from(path);
      let path = raw.canonicalize().map_err(|err| {
        DomainError::missing_target("path", format!("target path cannot be resolved: {err}"))
      })?;
      if !path.is_file() {
        return Err(DomainError::missing_target("path", "target path is not a file").into());
      }
      let path_buf = path.clone();
      let md5 = tokio::task::spawn_blocking(move || crate::ghidra::file_md5(&path_buf))
        .await
        .map_err(|err| DomainError::Internal {
          message: format!("file_md5 task panicked: {err}"),
        })??;
      session::open(state, md5, Some(&path), wait).await
    }
    (None, Some(md5)) => session::open(state, md5, None, wait).await,
    (None, None) => Err(
      DomainError::invalid_argument(
        "path/md5",
        "ghidra command `session.open` requires either 'path' or 'md5'",
      )
      .into(),
    ),
    (Some(_), Some(_)) => Err(
      DomainError::invalid_argument(
        "path/md5",
        "session.open accepts either 'path' or 'md5', not both",
      )
      .into(),
    ),
  }
}

/// Runs `analysis.start`.
async fn start_analysis(daemon: &Daemon, args: Value) -> Result<Output> {
  let args: AnalysisArgs = parse("analysis.start", &args)?;
  let state = &daemon.state;
  let wait = args
    .wait
    .then(|| millis_or(args.timeout_ms, state.config.timeouts.analysis_import));
  let md5 = args.md5;
  let job = analysis::start(state, md5.clone(), args.params, wait).await?;
  let text = if wait.is_some() && job.status == JobStatus::Completed {
    format!("Analysis completed for session {md5}")
  } else {
    format!("Analysis started for session {md5}")
  };
  Ok((text, json!({ "job": job })))
}

#[cfg(test)]
mod tests {
  use super::tool_definitions;

  /// Makes sure that Gemini can use the public tool as a function declaration.
  #[test]
  fn public_tool_contract_is_gemini_compatible() {
    let tools = tool_definitions();
    assert_eq!(tools.len(), 1);
    let tool = &tools[0];
    let name = tool["name"].as_str().expect("tool name");
    assert!(valid_function_name(name));

    let schema = &tool["inputSchema"];
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"].is_object());
    for unsupported in ["oneOf", "anyOf", "allOf", "$ref"] {
      assert!(
        schema.get(unsupported).is_none(),
        "public tool schema contains {unsupported}"
      );
    }
    assert!(schema.get("additionalProperties").is_none());
    assert!(tool.get("outputSchema").is_none());
  }

  /// Returns `true` for a Gemini function name that does not need conversion.
  fn valid_function_name(name: &str) -> bool {
    name.len() <= 64
      && name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
      && name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
  }
}
