# Troubleshooting

[English](troubleshooting.md) | [中文](zh/troubleshooting.md) | [日本語](ja/troubleshooting.md)

This runbook helps you diagnose and resolve common issues with `ghidra-mcp`.

## Contents

- [1. Headless executable discovery](#1-headless-executable-discovery)
- [2. Java 21 environment configuration](#2-java-21-environment-configuration)
- [3. Socket and pipe permissions](#3-socket-and-pipe-permissions)
- [4. Memory limits and large binary configuration](#4-memory-limits-and-large-binary-configuration)
- [5. Log diagnostics and error codes](#5-log-diagnostics-and-error-codes)

## 1. Headless executable discovery

### Symptoms

- The session transitions to status `error`.
- `last_error` shows: `cannot find analyzeHeadless`.

### Discovery precedence

The daemon searches for `analyzeHeadless` in this order:

1. `[ghidra].analyze_headless` in `config.toml`.
2. `[ghidra].home` in `config.toml`, or the `GHIDRA_INSTALL_DIR` and
   `GHIDRA_HOME` environment variables.
3. `analyzeHeadless` on system `PATH`.
4. `ghidraRun` on system `PATH`.
5. Standard directories: `/Applications/ghidra*`, `/opt/homebrew/Caskroom/ghidra/*`,
   `~/Applications`, `~`, `~/opt`.

### Solution

Set `GHIDRA_INSTALL_DIR` in your environment or MCP client settings:

```sh
export GHIDRA_INSTALL_DIR="/path/to/ghidra_12.1.4_PUBLIC"
```

On Windows:

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.1.4_PUBLIC"
```

As an alternative, configure `config.toml` in your persistent home directory:

```toml
[ghidra]
home = "/path/to/ghidra_12.1.4_PUBLIC"
```

## 2. Java 21 environment configuration

### Symptoms

- Ghidra crashes immediately when a session starts.
- The logs show: `UnsupportedClassVersionError: ... class file version 65.0`.

### Cause

Ghidra 11 or later and the embedded bridge runtime require a Java 21 JDK.
Older Java versions cannot run the class files.

### Solution

1. Verify your Java version:

   ```sh
   java -version
   ```

2. Install OpenJDK 21 or Eclipse Temurin 21.
3. Set `JAVA_HOME` to the Java 21 installation:

   ```sh
   export JAVA_HOME="/usr/lib/jvm/java-21-openjdk"
   ```

4. Restart your MCP client or daemon.

## 3. Socket and pipe permissions

### Symptoms

- The MCP client fails with `ConnectionRefused` or `PermissionDenied`.
- The proxy cannot connect to the daemon.

### Unix domain socket

The daemon stores the Unix socket in `<runtime_dir>/daemon.sock`.
The runtime directory requires mode `0700`.
The socket file requires mode `0600`.
The client process and daemon process must run under the same user UID.

Check permissions:

```sh
ls -ld /run/user/$UID/ghidra-mcp-*
ls -l /run/user/$UID/ghidra-mcp-*/daemon.sock
```

Fix directory permissions if necessary:

```sh
chmod 0700 /run/user/$UID/ghidra-mcp-*
```

### Windows named pipe

The daemon creates a named pipe `\\.\pipe\ghidra-mcp-<uuid>`.
The pipe enforces an owner-only DACL descriptor `D:P(A;;GA;;;OW)`.
The MCP client must run under the same Windows user account.
Sandbox environments or container processes without pipe access cannot connect.

## 4. Memory limits and large binary configuration

### Symptoms

- Ghidra analysis crashes with `java.lang.OutOfMemoryError`.
- Binaries larger than 50 MB or complex firmware cause high memory use.

### JVM heap configuration

Increase the JVM heap limit through `JAVA_TOOL_OPTIONS`:

```sh
export JAVA_TOOL_OPTIONS="-Xmx8G -Xms2G"
```

On Windows:

```powershell
$env:JAVA_TOOL_OPTIONS = "-Xmx8G -Xms2G"
```

### CPU concurrency limit

Limit the number of CPU cores for analysis in `config.toml`:

```toml
[analysis]
max_cpu = 2
```

Lower thread counts reduce peak memory use during parallel analysis.

### Log limits and truncation

The daemon bounds all log files (`daemon.log`, `stdout.log`, `stderr.log`) to 10 MiB.
When a log file reaches 10 MiB, the daemon rotates it and keeps up to 3 backups (`.1`, `.2`, `.3`).
The forwarder truncates individual log lines larger than 10 MiB with `[TRUNCATED_LOG_LINE]`.

## 5. Log diagnostics and error codes

### Log locations

Examine these log files to diagnose issues:

- Daemon log: `<runtime_dir>/daemon.log`
- Child process stdout: `<runtime_dir>/logs/<md5>/stdout.log`
- Child process stderr: `<runtime_dir>/logs/<md5>/stderr.log`

The daemon replaces sensitive bearer tokens in logs with `[REDACTED_TOKEN]`.

### JSON-RPC error codes

Tool calls return standard JSON-RPC 2.0 error codes in `structuredContent`:

| Code | Name | Cause | Resolution |
| --- | --- | --- | --- |
| `-32602` | `invalid_argument` | Absent or invalid command parameters. | Check parameters with `help`. |
| `-32001` | `session_lock_timeout` | Session lock timeout or request collision. | Wait for active command to finish. |
| `-32002` | `missing_target` | The daemon did not find the binary, session, or job ID. | Open session or upload binary first. |
| `-32000` | `disconnected` | Bridge disconnected or daemon shutdown in progress. | Reopen session with `session.open`. |
| `-32603` | `transaction_failed` | Internal database transaction or bridge fault. | Inspect child process logs. |
