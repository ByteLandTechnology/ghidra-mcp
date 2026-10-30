# First Steps

[English](getting-started.md) | [中文](zh/getting-started.md) | [日本語](ja/getting-started.md)

This guide helps you configure `ghidra-mcp` and connect your AI coding agents.
`ghidra-mcp` runs as a Model Context Protocol (MCP) server for Ghidra.
It provides headless binary analysis, decompilation, and symbol inspection.

## Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Client configuration](#client-configuration)
  - [Claude Desktop](#claude-desktop)
  - [Cursor](#cursor)
  - [Zed](#zed)
  - [Windsurf](#windsurf)
  - [Claude Code](#claude-code)
- [First analysis procedure](#first-analysis-procedure)
  - [1. Open a binary session](#1-open-a-binary-session)
  - [2. Start background analysis](#2-start-background-analysis)
  - [3. Poll job progress](#3-poll-job-progress)
  - [4. Inspect symbols and decompile](#4-inspect-symbols-and-decompile)
  - [5. Save changes and close](#5-save-changes-and-close)
- [Next steps](#next-steps)

## Prerequisites

Install these components before you use `ghidra-mcp`:

- Linux, macOS, or Windows.
- Java 21 JDK.
- Ghidra 12.1 or later with `analyzeHeadless` (`analyzeHeadless.bat` on Windows).

## Installation

### Prebuilt binary

Download the binary for your platform from
[GitHub Releases](https://github.com/ByteLandTechnology/ghidra-mcp/releases).

| Platform | x86_64 | ARM64 |
| --- | --- | --- |
| macOS | `ghidra-mcp-macos-x86_64` | `ghidra-mcp-macos-arm64` |
| Linux | `ghidra-mcp-linux-x86_64` | `ghidra-mcp-linux-arm64` |
| Windows | `ghidra-mcp-windows-x86_64.exe` | `ghidra-mcp-windows-arm64.exe` |

1. Rename the downloaded file to `ghidra-mcp` (`ghidra-mcp.exe` on Windows).
2. On Linux and macOS, make the binary executable:

   ```sh
   chmod +x ghidra-mcp
   ```

3. Set `GHIDRA_INSTALL_DIR` to your Ghidra directory.

### Build from source

To build from source, use this procedure:

1. Install a Rust toolchain.
2. Clone the repository with its submodules:

   ```sh
   git clone --recurse-submodules https://github.com/ByteLandTechnology/ghidra-mcp.git
   ```

3. Change to the repository directory:

   ```sh
   cd ghidra-mcp
   ```

4. Build the release executable:

   ```sh
   cargo xtask build --release --locked --bin ghidra-mcp
   ```

The build embeds the Java bridge runtime into the compiled binary.
The output binary is `target/release/ghidra-mcp` (`ghidra-mcp.exe` on Windows).

## Client configuration

Configure your MCP client to connect to `ghidra-mcp`.

### Claude Desktop

Add `ghidra` to your `claude_desktop_config.json` file.

File locations:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Configuration snippet:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/ghidra-mcp",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.4_PUBLIC"
      }
    }
  }
}
```

### Cursor

Add `ghidra-mcp` to `.cursor/mcp.json` in your workspace or global settings.

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/ghidra-mcp",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.4_PUBLIC"
      }
    }
  }
}
```

### Zed

Add `ghidra` under `context_servers` in `~/.config/zed/settings.json`.

```json
{
  "context_servers": {
    "ghidra": {
      "command": {
        "path": "/path/to/ghidra-mcp",
        "args": [],
        "env": {
          "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.4_PUBLIC"
        }
      }
    }
  }
}
```

### Windsurf

Add `ghidra` to `~/.codeium/windsurf/mcp_config.json`.

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/ghidra-mcp",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.1.4_PUBLIC"
      }
    }
  }
}
```

### Gemini CLI

Register `ghidra-mcp` as a local stdio MCP server:

```sh
gemini mcp add --transport stdio --scope project ghidra-mcp /path/to/ghidra-mcp
```

For a daemon that already runs, use Streamable HTTP:

```sh
gemini mcp add --transport http --scope project \
  ghidra-mcp http://127.0.0.1:18489/mcp
```

Legacy clients can use SSE on the same URL:

```sh
gemini mcp add --transport sse --scope project \
  ghidra-mcp http://127.0.0.1:18489/mcp
```

Use the `http` transport for new configurations. Use `sse` only when the client
needs the legacy SSE transport.

### Claude Code

Register `ghidra-mcp` as a local stdio MCP server:

```sh
claude mcp add --transport stdio --scope local ghidra-mcp -- /path/to/ghidra-mcp
```

Verify the server connection status:

```sh
claude mcp get ghidra-mcp
```

## First analysis procedure

The daemon shows `ghidra_help` and one MCP tool for each domain.
Each domain tool takes an `operation` and its `params`.
An operation that names one session also takes the `md5` of that session.
This document writes an operation as the tool name and the operation name, for example `ghidra_session open`.

Before the first call to an operation, call `ghidra_help` with its domain and operation.
For example, call `ghidra_help` with:

```json
{ "domain": "ghidra_memory", "operation": "read" }
```

The result has an `inputSchema` for the contents of `params` and an `md5` rule for the top-level argument.
For `read`, put `address` in `params.selector`. The optional `length` is in `params` and defaults to 256 bytes.
When an operation needs `md5`, use the file digest or the MD5 of a session that is available.
The MD5 has exactly 32 hexadecimal characters.

### 1. Open a binary session

Open a local binary file with `ghidra_session`:

```json
{
  "operation": "open",
  "params": { "path": "/path/to/target_binary" }
}
```

The daemon calculates the MD5 hash and copies the binary into persistent storage.
The call returns a launch job record.
Check the session status with `ghidra_session`:

```json
{
  "operation": "get",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

The `status` field shows `ready` when the session is ready.

### 2. Start background analysis

Start auto-analysis on the opened binary with `ghidra_analysis`:

```json
{
  "operation": "start",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

The call returns a job record with `status: "running"`.

### 3. Poll job progress

Poll the job status at intervals of 500 ms with `ghidra_job`:

```json
{
  "operation": "get",
  "params": { "jobId": "job-12345" }
}
```

As an alternative, wait for the job to complete:

```json
{
  "operation": "wait",
  "params": { "jobId": "job-12345", "timeoutMs": 60000 }
}
```

The job record shows `status: "completed"` when analysis finishes.

### 4. Inspect symbols and decompile

List the functions in the binary with `ghidra_function`:

```json
{
  "operation": "list",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

Inspect symbols with `ghidra_symbol`:

```json
{
  "operation": "list",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

Decompile a function at an entry point with `ghidra_decompilation`:

```json
{
  "operation": "get",
  "md5": "0123456789abcdef0123456789abcdef",
  "params": { "selector": { "entry": "ram:140001000" } }
}
```

The bridge returns structured C pseudocode, signatures, and local variables.

### 5. Save changes and close

Save program changes to the Ghidra project with `ghidra_program`:

```json
{
  "operation": "save",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

Close the active session with `ghidra_session`:

```json
{
  "operation": "close",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

## Next steps

- Read [Troubleshooting](troubleshooting.md) for solutions to common issues.
- Read [Architecture](architecture.md) for detailed system internals.
