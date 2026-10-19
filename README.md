# ghidra-mcp

[English](README.md) | [中文](README.zh-CN.md) | [日本語](README.ja-JP.md)

![Rust](https://img.shields.io/badge/Rust-2021-000000?logo=rust)
![MCP](https://img.shields.io/badge/MCP-stdio%20%7C%20HTTP-1f6feb)
![CI](https://github.com/ByteLandTechnology/ghidra-mcp/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

`ghidra-mcp` is an MCP server and a command-line tool for headless Ghidra analysis.

One local daemon runs the Ghidra sessions on Linux, macOS and Windows.
MCP clients connect to the daemon through stdio or HTTP.
The command-line tool uses the same daemon.
The MD5 of a binary identifies its session for all clients.

> [!IMPORTANT]
> The daemon keeps configuration, binaries and analysis in the **persistent home**.
> The default persistent home is `~/.ghidra-mcp` on Linux and macOS, and `%LOCALAPPDATA%\ghidra-mcp` on Windows.
> To use a different directory, set `GHIDRA_MCP_HOME`.
> The daemon keeps temporary files in a private **runtime directory**.
> If the daemon does not run, stdio clients and the command-line tool start it.

![System Architecture](docs/img/architecture.svg)

## Contents

- [Features](#features)
- [Get started](#get-started)
- [Usage](#usage)
- [Use with coding agents](#use-with-coding-agents)
- [Configuration](#configuration)
- [The MCP tools](#the-mcp-tools)
- [Files and directories](#files-and-directories)
- [Validation and releases](#validation-and-releases)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Contribute](#contribute)
- [License](#license)

## Features

- **MCP through stdio, Streamable HTTP, or legacy SSE.** One daemon keeps the shared state.
- **Command-line client.** It lists the tools locally. It calls the tools through the daemon.
- **Sessions identified by MD5.** The daemon uses a session again or opens the saved analysis again.
- **Persistent sessions and jobs.** Sessions and analysis jobs continue after a client disconnects.
- **Remote upload.** A client that is not on the daemon host sends a binary through a separate HTTP endpoint.
- **Full Ghidra access.** The Java bridge gives program data, functions, decompilation, symbols, references, memory and comments.
- **One executable.** The executable contains the bridge JAR and its launcher script.
- **Background jobs.** `ghidra_job get` and `ghidra_job wait` monitor a long analysis.

Sessions can change the program by default.
Coding agents must get approval from the user before they use an operation that changes the program.

## Get started

For client setup snippets and walkthroughs, read the
[First Steps guide](docs/getting-started.md).

### Prerequisites

- Linux, macOS or Windows.
- Java 21.
- A local Ghidra installation that has `analyzeHeadless` (`analyzeHeadless.bat` on Windows).

### Use a prebuilt executable

1. Download the file for your platform from [GitHub Releases](https://github.com/ByteLandTechnology/ghidra-mcp/releases).

   | Platform | x86_64 | ARM64 |
   | --- | --- | --- |
   | macOS | `ghidra-mcp-macos-x86_64` | `ghidra-mcp-macos-arm64` |
   | Linux | `ghidra-mcp-linux-x86_64` | `ghidra-mcp-linux-arm64` |
   | Windows | `ghidra-mcp-windows-x86_64.exe` | `ghidra-mcp-windows-arm64.exe` |

2. Rename the file to `ghidra-mcp` (`ghidra-mcp.exe` on Windows).
3. On Linux and macOS, make the file executable with `chmod +x ghidra-mcp`.
4. Make sure that the executable can find Ghidra (see [Find Ghidra](#find-ghidra)). For example, on Windows:

   ```powershell
   $env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_12.1.4_PUBLIC'
   .\ghidra-mcp.exe tools
   ```

5. Add the executable to your MCP client:

   ```json
   {
     "command": "C:\\Tools\\ghidra-mcp.exe",
     "args": []
   }
   ```

The executable needs only Ghidra and Java.
It writes the bridge files into the runtime directory when it opens a session.

### Build from source

To build from source, you also need:

- A Rust toolchain.
- The `bridge/` submodule. The build uses the Gradle wrapper of the submodule.
- A Ghidra installation in `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME`. The bridge compiles against this installation.

1. If you cloned the repository without submodules, get the bridge:

   ```sh
   git submodule update --init --recursive
   ```

2. Build the release executable:

   ```sh
   cargo xtask build --release --locked --bin ghidra-mcp
   ```

The result is `target/release/ghidra-mcp` (`ghidra-mcp.exe` on Windows).
This one file is the complete distribution.

The command `cargo xtask build` builds the bridge with Gradle.
Then it embeds the bridge JAR and `Bridge.java` in the executable.
The operation catalog comes from the bridge contract `bridge/docs/asyncapi.yaml` at compile time.

To embed a bridge JAR that you built before, set `GHIDRA_MCP_BRIDGE_JAR`.
A relative path starts at the workspace root.
The build then makes only `Bridge.java` and does not compile the bridge.

### Find Ghidra

The daemon finds `analyzeHeadless` in this order:

1. `[ghidra].analyze_headless` in `config.toml`.
2. The installation in `[ghidra].home`, `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME`.
3. `analyzeHeadless` on `PATH`.
4. The installation of `ghidraRun` on `PATH`.
5. On Unix, the Homebrew Cellar and directories named `ghidra*` in `/Applications`, `~`, `~/Applications` and `~/opt`.

> [!TIP]
> If a computer has more than one Ghidra installation, set `GHIDRA_INSTALL_DIR`.

## Usage

The default configuration does not need environment variables.
These optional variables change the defaults:

| Variable | Purpose |
| --- | --- |
| `GHIDRA_INSTALL_DIR` | The Ghidra installation directory. |
| `GHIDRA_HOME` | Another name for the installation directory. `GHIDRA_INSTALL_DIR` has priority. |
| `GHIDRA_MCP_HOME` | The persistent home. |

Ghidra also uses the standard Java variables `JAVA_HOME` and `JAVA_TOOL_OPTIONS`.
On Unix, `XDG_RUNTIME_DIR` and `TMPDIR` set the location of the runtime directory.

### Stdio server

An MCP client starts `ghidra-mcp` without arguments and talks to it through stdio:

```json
{
  "command": "/path/to/ghidra-mcp",
  "args": []
}
```

This process sends each tool call to the daemon.
If the daemon does not run, the process starts it.
The process connects to the daemon through a local socket.
On Unix, the socket is a private Unix domain socket.
On Windows, the socket is a named pipe.

The process reuses this connection across tool calls to avoid repeated handshake delays.
If the daemon stops, the process reconnects on the next call.

To run from a source checkout, use `cargo run --` as the command.

### HTTP server

To run the daemon in the foreground, use this command:

```sh
ghidra-mcp --daemon
```

The daemon serves these endpoints on one listener:

| Endpoint | Purpose |
| --- | --- |
| `http://127.0.0.1:18489/mcp` | MCP through Streamable HTTP or legacy SSE. |
| `/upload` | Binary uploads. |
| `/ws/agent` | The WebSocket of the Ghidra bridge. |

The daemon accepts only loopback addresses.
To use a different address, use `--listen`:

```sh
ghidra-mcp --daemon --listen 127.0.0.1:18490
```

With `--listen 127.0.0.1:0`, the system selects a free port.
The daemon writes the address in `server.json` and `daemon.log` in the runtime directory.

The daemon continues to run after all clients disconnect.
To stop a foreground daemon, press Ctrl-C.
On Unix, `SIGINT`, `SIGTERM` and `SIGHUP` also stop it.
When the daemon stops, it closes its Ghidra sessions.
You can open the saved projects again later.

### Command-line tool

The command-line tool uses the same tool catalog as MCP.

To list the tools without a daemon, use this command:

```sh
ghidra-mcp tools
```

To call a tool through the daemon, use this command:

```sh
ghidra-mcp call ghidra_session '{"operation":"list"}'
```

`call TOOL [JSON]` accepts one JSON object. The default is `{}`.
If necessary, the command starts the daemon.
The command writes `structuredContent` as formatted JSON.

| Result | Output | Exit code |
| --- | --- | --- |
| The call is successful. | The result on stdout. | 0 |
| The call fails. | The error on stderr. | 1 |
| The arguments are not valid. | The usage on stderr. | 2 |
| `--help` or `--version`. | The text on stdout. | 0 |

### Upload a binary from a remote client

Use this procedure when the client is not on the daemon host.

![Remote Upload Sequence](docs/img/remote_upload.svg)

1. On the client, calculate the MD5 and the size in bytes of the file.
2. Call the `ghidra_upload` tool:

   ```json
   {"operation":"prepare","md5":"0123456789abcdef0123456789abcdef","params":{"fileName":"program.bin","size":1024}}
   ```

   `fileName` is a display name. It must not contain a directory.
3. Read the result. It contains these fields:
   - `method`: `POST`.
   - `url`: An absolute URL for HTTP calls, for example `https://host/ghidra/upload`.
     Other transports return `upload`, relative to the MCP URL.
   - `headers`: a single-use `Authorization: Bearer` credential and `Content-Type: application/octet-stream`.
   - `expiresAt`: the expiry time in Unix seconds.
4. Send the file as the raw request body with the headers from the result:

   ```sh
   curl -X POST 'https://host/ghidra/upload' \
     -H 'Authorization: Bearer <credential>' \
     -H 'Content-Type: application/octet-stream' \
     --data-binary @program.bin
   ```

5. Read the response:
   - HTTP `200`: the session is ready.
   - HTTP `202`: the session starts. Use `ghidra_job wait` with the returned `jobId`.

You do not need a separate `ghidra_session open` call.

> [!NOTE]
> - The upload goes directly to disk. It can be larger than the MCP request limit. The daemon accepts HTTP chunked transfer.
> - You must start the upload within ten minutes after `ghidra_upload prepare`.
>   This limit does not apply to an active upload.
> - The request uses the credential when it starts. After an upload fails, get a new credential.
> - The daemon examines the size and the MD5 before it saves the binary. A failed upload leaves no file and no session.
> - If Ghidra does not start, the binary stays saved. Use `ghidra_session open` with the MD5 to retry.
> - A reverse proxy must send both `/mcp` and `/upload` to the daemon, with the same prefix.

The server uses `Forwarded` host and protocol values first, then `X-Forwarded-Host` and
`X-Forwarded-Proto`.
`X-Forwarded-Prefix` supplies a path prefix that the proxy removed.

The server can also use an absolute HTTP or HTTPS `Referer` whose path ends in `/mcp`.
It does not use a Referer that points to a client page.
Without these headers, the server uses the HTTP request address.
An invalid protocol or path prefix leaves the URL relative.
The proxy must replace client-supplied address headers with the correct public values.

## Use with coding agents

Coding agents start `ghidra-mcp` as a stdio server, or connect to the HTTP URL.
Agents that use the same runtime directory share one daemon.

![Reverse Engineering Flow](docs/img/reverse_engineering_flow.svg)

For Claude Code, add the executable as a local stdio server:

```sh
claude mcp add --transport stdio --scope local ghidra-mcp -- /absolute/path/to/ghidra-mcp
```

To examine the connection, use `claude mcp get ghidra-mcp` or the `/mcp` panel.
The status must be `Status: ✓ Connected`.

Use this procedure in an agent:

1. Open the binary:
   - For a binary that the daemon saved before, call `ghidra_session` with `{"operation":"open","md5":"..."}`.
   - For a file on the daemon host, call `ghidra_session` with `{"operation":"open","params":{"path":"..."}}`. The daemon calculates the MD5 and saves the binary.
   - For a file on a remote client, upload it (see [Upload a binary from a remote client](#upload-a-binary-from-a-remote-client)).
2. If the session starts, call `ghidra_job` with `{"operation":"wait","params":{"jobId":"...","timeoutMs":...}}`.
   You can use `ghidra_job get` to monitor the job.
3. Confirm the ready status with `ghidra_session get`.
4. Start the analysis: call `ghidra_analysis` with `{"operation":"start","md5":"..."}`.
5. Monitor the analysis job with `ghidra_job get` or `ghidra_job wait`.
6. Use the domain tools of the bridge, for example `ghidra_program get`, `ghidra_function list` and `ghidra_data_type create`.
7. Save the analysis and the changes with `ghidra_program save`. The session stays open.
8. Get approval from the user before you use an operation that changes the program.

A session summary contains only `md5`, `fileName`, `status` and `connected`.
All session operations use `md5`. There is no separate session ID.
`ghidra_session list` is optional.
For an MD5 that the daemon does not know, the daemon tells you to upload the binary.

## Configuration

At the first start, the daemon writes a default `config.toml` in the persistent home.
This example shows all the keys with their default values:

```toml
[ghidra]
home = ""
analyze_headless = ""

[analysis]
max_cpu = 4

[timeouts]
process_spawn_timeout_sec = 30
analysis_import_timeout_sec = 1800
bridge_connect_timeout_sec = 30
agent_ready_timeout_sec = 30
bridge_disconnect_grace_sec = 5
graceful_kill_timeout_sec = 10
force_kill_timeout_sec = 5
rpc_ms = 30000
daemon_start_timeout_sec = 8
ipc_handshake_timeout_sec = 5
```

| Key | Purpose |
| --- | --- |
| `ghidra.home` | The Ghidra installation directory. |
| `ghidra.analyze_headless` | The path of `analyzeHeadless`. |
| `analysis.max_cpu` | The value of `analyzeHeadless -max-cpu`. |
| `timeouts.process_spawn_timeout_sec` | The time to start the Ghidra process. |
| `timeouts.analysis_import_timeout_sec` | The time to import a binary. It is also the default wait for `ghidra_analysis start`. |
| `timeouts.bridge_connect_timeout_sec` | A part of the total time to start a session. |
| `timeouts.agent_ready_timeout_sec` | The time for the bridge to complete its handshake. |
| `timeouts.bridge_disconnect_grace_sec` | The time for a process to stop by itself after its bridge disconnects or its session closes. |
| `timeouts.graceful_kill_timeout_sec` | The time for a process to stop after the daemon tells it to stop. |
| `timeouts.force_kill_timeout_sec` | The time for a process to stop after the daemon kills it. |
| `timeouts.rpc_ms` | The time for one bridge request, in milliseconds. |
| `timeouts.daemon_start_timeout_sec` | The time to wait for a daemon in proxy or CLI mode. |
| `timeouts.ipc_handshake_timeout_sec` | The timeout for the IPC handshake between proxy and daemon. |

- An empty string for `home` or `analyze_headless` has the same effect as no value.
- The daemon ignores other sections and keys. The file must be valid TOML.
- Java temporary files always go into the `tmp/` directory of the runtime directory.
- The daemon does not accept the removed keys `ghidra.java_tmp_dir`, `ghidra.script_path` and `ghidra.bridge_script`. Remove them from your file.

## The MCP tools

`tools/list` shows 18 MCP tools: `ghidra_help` and one tool for each domain.
The domains and the operations are the same as in the MCP server of the bridge.
This document writes an operation as the tool name and the operation name, for example `ghidra_session open`.

A domain tool has these arguments:

- `operation`: necessary. The operation in the domain, for example `list`.
- `md5`: the MD5 of the session that the operation names. It is never in `params`. Each operation has an md5 rule: `required`, `optional` or `absent`.
- `params`: the parameters of the operation. The default is `{}`.

| Tool | Operations | Runs in |
| --- | --- | --- |
| `ghidra_session` | `open`, `list`, `get`, `close` | The daemon. |
| `ghidra_upload` | `prepare` | The daemon. |
| `ghidra_job` | `get`, `wait` | The daemon. |
| `ghidra_analysis` | `start`, `get` | `start`: the daemon, then the bridge. `get`: the bridge. |
| `ghidra_bridge`, `ghidra_program`, `ghidra_address`, `ghidra_memory`, `ghidra_listing`, `ghidra_global_variable`, `ghidra_function`, `ghidra_decompilation`, `ghidra_symbol`, `ghidra_reference`, `ghidra_comment`, `ghidra_data_type`, `ghidra_batch` | The bridge methods of the domain. | The bridge of the session. |

The bridge contract `bridge/docs/asyncapi.yaml` gives the bridge methods, their schemas and their `read_only` effects.
The daemon sends only the methods in this contract.
It does not show `interface.get` and `session.shutdown`. To stop a session, use `ghidra_session close`.
The parameters use the objects of the bridge, for example `selector`, `filter`, `page`, `patch` and `resource`.

Examples for `ghidra_function get` and `ghidra_comment upsert`:

```json
{"operation":"get","md5":"0123456789abcdef0123456789abcdef","params":{"selector":{"entry":"ram:00100000"}}}
{"operation":"upsert","md5":"0123456789abcdef0123456789abcdef","params":{"resource":{"address":"ram:00100000","type":"eol","text":"checked"}}}
```

The `ghidra_help` tool describes all tools:

- `{}` lists the domain tools.
- `{"domain":"function"}` lists the operations of one domain.
- `{"domain":"function","operation":"list"}` shows the full parameter schema, the md5 rule and the effects of one operation. The effects are the same as in the bridge contract, for example `read_only`, `mutates_program` and `destructive`.

If the Ghidra process does not start, the session goes to `error` and its launch job goes to `failed`.
With `wait=false`, `ghidra_session open` returns immediately. Use `ghidra_session get` and `ghidra_job get` to see the result.
With `wait=true`, `ghidra_session open` waits and returns the error.

The MD5 hash identifies each session.
The daemon manages session states through a finite state machine:

![Session Lifecycle](docs/img/session_lifecycle.svg)

When a tool call fails, `structuredContent` contains a machine-readable JSON-RPC error code:
- `-32602` (`invalid_argument`): An unknown tool, or invalid or absent tool arguments or operation parameters.
- `-32001` (`session_lock_timeout`, `agent_timeout`, `request_in_flight`): Lock timeout or request collision.
- `-32002` (`missing_target`): Unknown binary MD5, session, job ID, domain, or operation.
- `-32000` (`disconnected`, `shutting_down`): Disconnected bridge session or daemon shutdown.
- `-32603` (`transaction_failed`, `bridge_internal`, `internal_error`): Ghidra transaction failure or internal error.
Database transaction failures return code `-32603` (`transaction_failed`).
They do not return as invalid arguments.

## Files and directories

On Unix, the persistent data and the runtime data are in different locations:

```text
GHIDRA_MCP_HOME/                 # default: ~/.ghidra-mcp
|-- config.toml
`-- projects/<md5>/
    |-- binary                  # The saved binary, with a fixed name
    |-- binary.json             # The original file name
    `-- ghidra/
        |-- project.gpr
        `-- project.rep/

<runtime-base>/ghidra-mcp-<uid>/
|-- projects -> GHIDRA_MCP_HOME/projects
|-- sessions/<md5>/session.json
|-- logs/<md5>/
|-- tmp/
|-- daemon.sock
|-- daemon.log
|-- daemon.lock
|-- server.json
|-- ghidra-bridge.jar
`-- Bridge.java
```

- The runtime base is `XDG_RUNTIME_DIR` on Linux. Otherwise, it is the temporary directory of the system.
- If the runtime base has a hidden segment, the daemon uses `/tmp` instead. Ghidra does not accept hidden segments.
- The runtime directory has the mode `0700`. The daemon log and the lock file have the mode `0600`.
- Ghidra cannot open a project in a hidden directory. For this reason, the daemon gives Ghidra the `projects` symbolic link. The project files stay in the persistent home.
- If the `projects` path holds a different object, the daemon stops with an error. It does not replace the object.

On Windows, the default layout is:

```text
%LOCALAPPDATA%\ghidra-mcp\
|-- config.toml
|-- projects\<md5>\
|   |-- binary
|   |-- binary.json
|   `-- ghidra\
|       |-- project.gpr
|       `-- project.rep\
`-- run\
    |-- sessions\<md5>\session.json
    |-- logs\<md5>\
    |-- tmp\
    |-- daemon.log
    |-- daemon.lock
    |-- server.json
    |-- ghidra-bridge.jar
    `-- Bridge.java
```

- `GHIDRA_MCP_HOME` moves the configuration and the projects. The runtime directory stays in `%LOCALAPPDATA%\ghidra-mcp\run`.
- Ghidra opens the project directly. There is no symbolic link.
- Clients connect through a named pipe. `server.json` contains its random name. Only the owner can connect. Remote clients cannot connect.

On all platforms:

- One daemon runs for each runtime directory. A file lock enforces this rule. There is no PID file.
- Each runtime directory uses one persistent home. To change `GHIDRA_MCP_HOME`, stop the daemon and clear the runtime directory first. The projects in the old home stay available.
- You can delete the runtime directory when the daemon does not run. Then `ghidra_session open` with the MD5 opens the saved project again.
- The daemon opens a project again when `project.gpr` and `project.rep` exist. Ghidra replays its recovery journal.
- The daemon does not change a project directory that it does not recognize. It shows an error.
- The daemon bounds all log files (`daemon.log`, `stdout.log`, `stderr.log`) to 10 MiB.
- The forwarder truncates oversized log lines. It replaces lines above 10 MiB with `[TRUNCATED_LOG_LINE]`.
- When a log file reaches 10 MiB, the daemon rotates it and keeps up to three backups (`.1`, `.2`, `.3`).
- The daemon replaces sensitive authentication tokens in log lines with `[REDACTED_TOKEN]`.
- On Windows, the daemon closes active write handles before it renames log files.
- The daemon rotates `daemon.log` before it opens a file larger than 10 MiB.

## Validation and releases

To do the same checks as CI, use these commands:

```sh
cargo xtask ci
cargo xtask build --release --locked --bin ghidra-mcp
```

Or run the checks separately:

```sh
cargo xtask check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked
```

CI builds release executables on macOS, Linux and Windows, for x86_64 and ARM64.
Each push to `main`, each pull request and each manual run starts all six builds.
A failed build does not stop the other builds.
The Windows executables link the C runtime statically.

release-please sets the versions from the Conventional Commits on `main`:

- `fix:` gives a patch release.
- `feat:` gives a minor release.
- `!` or `BREAKING CHANGE:` gives a major release.

release-please opens a release pull request.
This pull request updates the workspace version, `Cargo.lock`, `CHANGELOG.md` and the release manifest.
After you merge it, release-please creates a version tag and a draft release at a fixed commit.
All six builds and the dependency audit use that commit.

After those checks pass, CI attaches the executables, SHA-256 checksums and license texts.
Then CI publishes the draft.
Failed checks leave the release as a draft. Rerun the failed jobs.
CI uses the default `GITHUB_TOKEN`. You do not need other secrets.

> [!NOTE]
> - The repository must let GitHub Actions make pull requests.
> - A CI run for a release pull request from `GITHUB_TOKEN` must have maintainer approval. Approve the run before you merge.

## Troubleshooting

For runbooks about Ghidra discovery, Java 21, socket permissions, memory, and logs,
read the [Troubleshooting guide](docs/troubleshooting.md).

### The daemon cannot find `analyzeHeadless`

- Set `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME`.
- Alternatively, put `analyzeHeadless` or `ghidraRun` on `PATH`.

### The bridge JAR is absent

- Make sure that `ghidra-bridge.jar` is in the runtime directory.
- If you changed the bridge source, run `cargo xtask build` again. The xtask command builds and embeds the bridge again.

### The daemon does not start

- Read `daemon.log` in the runtime directory.
- Make sure that no other program uses the HTTP address. To let the system select a free port, use `--listen 127.0.0.1:0`.
- `daemon.lock` stops a second daemon in the same runtime directory. Do not delete the runtime files while the daemon runs.

## Documentation

- [First Steps](docs/getting-started.md): configuration steps and the first analysis procedure.
- [Troubleshooting](docs/troubleshooting.md): runbooks for discovery, Java 21, permissions, memory, and logs.
- [Architecture](docs/architecture.md): processes, request flows, session lifecycle, concurrency, process ownership and security.
- API documentation of each module and item: `cargo doc --no-deps --document-private-items --open`.
- [Security policy](SECURITY.md): deployment and vulnerability reports.
- [Changelog](CHANGELOG.md).
- The Java bridge has its own documents: [`bridge/README.md`](bridge/README.md), [`bridge/docs/protocol.md`](bridge/docs/protocol.md), [`bridge/docs/api.md`](bridge/docs/api.md) and [`bridge/docs/development.md`](bridge/docs/development.md).

## Contribute

We welcome contributions.
[CONTRIBUTING.md](CONTRIBUTING.md) gives the prerequisites, the standards for code and text, and the extension procedures.
The [code of conduct](CODE_OF_CONDUCT.md) applies to all participants.

The Rust code is in `src/`.
The `xtask/` directory contains automation tools.
The Java bridge is a Git submodule.
Clone with `--recurse-submodules`, or use `git submodule update --init --recursive`.

## License

The [MIT License](LICENSE) applies to this project.
The Java bridge in `bridge/` has a separate license. See [`bridge/LICENSE`](bridge/LICENSE).
