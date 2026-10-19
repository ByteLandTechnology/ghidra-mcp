# ghidra-mcp

[English](README.md) | [中文](README.zh-CN.md) | [日本語](README.ja-JP.md)

![Rust](https://img.shields.io/badge/Rust-2021-000000?logo=rust)
![MCP](https://img.shields.io/badge/MCP-stdio%20%7C%20HTTP-1f6feb)
![CI](https://github.com/ByteLandTechnology/ghidra-mcp/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

`ghidra-mcp` 是用于 Ghidra 无头分析的 MCP 服务器和命令行工具。

一个本地守护进程在 Linux、macOS 和 Windows 上运行 Ghidra 会话。
MCP 客户端通过 stdio 或 HTTP 连接守护进程。
命令行工具使用同一个守护进程。
二进制文件的 MD5 在所有客户端之间标识它的会话。

> [!IMPORTANT]
> 守护进程把配置、二进制文件和分析结果保存在**持久主目录**中。
> 持久主目录的默认位置在 Linux 和 macOS 上是 `~/.ghidra-mcp`，在 Windows 上是 `%LOCALAPPDATA%\ghidra-mcp`。
> 要使用其他目录，请设置 `GHIDRA_MCP_HOME`。
> 守护进程把临时文件保存在私有的**运行时目录**中。
> 如果守护进程没有运行，stdio 客户端和命令行工具会启动它。

![体系架构](docs/img/architecture.svg)

## 目录

- [功能](#功能)
- [快速开始](#快速开始)
- [使用方法](#使用方法)
- [与编码代理一起使用](#与编码代理一起使用)
- [配置](#配置)
- [MCP 工具](#mcp-工具)
- [文件和目录](#文件和目录)
- [验证和发布](#验证和发布)
- [故障排除](#故障排除)
- [文档](#文档)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

## 功能

- **通过 stdio、Streamable HTTP 或旧式 SSE 提供 MCP。** 一个守护进程保存共享状态。
- **命令行客户端。** 在本地列出工具，并通过守护进程调用这些工具。
- **用 MD5 标识会话。** 守护进程重用会话，或重新打开已保存的分析。
- **持久的会话和作业。** 客户端断开连接后，会话和分析作业继续运行。
- **远程上传。** 不在守护进程主机上的客户端通过单独的 HTTP 端点发送二进制文件。
- **完整的 Ghidra 访问。** Java 桥接提供程序数据、函数、反编译、符号、引用、内存和注释。
- **单个可执行文件。** 可执行文件包含桥接 JAR 及其启动脚本。
- **后台作业。** `ghidra_job get` 和 `ghidra_job wait` 监视长时间运行的分析。

默认情况下，会话可以修改程序。
编码代理在使用会修改程序的操作之前，必须获得用户的批准。

## 快速开始

有关客户端配置片段和首次分析步骤，请参阅[第一步指南](docs/zh/getting-started.md)。

### 前提条件

- Linux、macOS 或 Windows。
- Java 21。
- 本地 Ghidra 安装，包含 `analyzeHeadless`（Windows 上为 `analyzeHeadless.bat`）。

### 使用预构建的可执行文件

1. 从 [GitHub Releases](https://github.com/ByteLandTechnology/ghidra-mcp/releases) 下载适合您平台的文件。

   | 平台 | x86_64 | ARM64 |
   | --- | --- | --- |
   | macOS | `ghidra-mcp-macos-x86_64` | `ghidra-mcp-macos-arm64` |
   | Linux | `ghidra-mcp-linux-x86_64` | `ghidra-mcp-linux-arm64` |
   | Windows | `ghidra-mcp-windows-x86_64.exe` | `ghidra-mcp-windows-arm64.exe` |

2. 将文件重命名为 `ghidra-mcp`（Windows 上为 `ghidra-mcp.exe`）。
3. 在 Linux 和 macOS 上，用 `chmod +x ghidra-mcp` 使文件可执行。
4. 确保可执行文件能找到 Ghidra（参见[查找 Ghidra](#查找-ghidra)）。例如，在 Windows 上：

   ```powershell
   $env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_12.1.4_PUBLIC'
   .\ghidra-mcp.exe tools
   ```

5. 将可执行文件添加到您的 MCP 客户端：

   ```json
   {
     "command": "C:\\Tools\\ghidra-mcp.exe",
     "args": []
   }
   ```

可执行文件只需要 Ghidra 和 Java。
它在打开会话时把桥接文件写入运行时目录。

### 从源代码构建

从源代码构建还需要：

- Rust 工具链。
- `bridge/` 子模块。构建使用该子模块的 Gradle wrapper。
- `GHIDRA_INSTALL_DIR` 或 `GHIDRA_HOME` 中的 Ghidra 安装。桥接针对此安装进行编译。

1. 如果克隆仓库时没有包含子模块，请获取桥接：

   ```sh
   git submodule update --init --recursive
   ```

2. 构建发布版可执行文件：

   ```sh
   cargo xtask build --release --locked --bin ghidra-mcp
   ```

结果是 `target/release/ghidra-mcp`（Windows 上为 `ghidra-mcp.exe`）。
这一个文件就是完整的发行版。

`cargo xtask build` 命令用 Gradle 构建桥接。
然后它把桥接 JAR 和 `Bridge.java` 嵌入可执行文件。
操作目录在编译时来自桥接契约 `bridge/docs/asyncapi.yaml`。

要嵌入事先构建好的桥接 JAR，请设置 `GHIDRA_MCP_BRIDGE_JAR`。
相对路径从工作区根目录开始。
此时构建只生成 `Bridge.java`，不编译桥接。

### 查找 Ghidra

守护进程按以下顺序查找 `analyzeHeadless`：

1. `config.toml` 中的 `[ghidra].analyze_headless`。
2. `[ghidra].home`、`GHIDRA_INSTALL_DIR` 或 `GHIDRA_HOME` 中的安装。
3. `PATH` 上的 `analyzeHeadless`。
4. `PATH` 上的 `ghidraRun` 所属的安装。
5. 在 Unix 上，依次查找 Homebrew Cellar，以及 `/Applications`、`~`、`~/Applications` 和 `~/opt` 中名为 `ghidra*` 的目录。

> [!TIP]
> 如果一台计算机上有多个 Ghidra 安装，请设置 `GHIDRA_INSTALL_DIR`。

## 使用方法

默认配置不需要环境变量。
以下可选变量可以更改默认值：

| 变量 | 用途 |
| --- | --- |
| `GHIDRA_INSTALL_DIR` | Ghidra 安装目录。 |
| `GHIDRA_HOME` | 安装目录的另一个名称。`GHIDRA_INSTALL_DIR` 优先。 |
| `GHIDRA_MCP_HOME` | 持久主目录。 |

Ghidra 还使用标准 Java 变量 `JAVA_HOME` 和 `JAVA_TOOL_OPTIONS`。
在 Unix 上，`XDG_RUNTIME_DIR` 和 `TMPDIR` 决定运行时目录的位置。

### Stdio 服务器

MCP 客户端不带参数启动 `ghidra-mcp`，并通过 stdio 与它通信：

```json
{
  "command": "/path/to/ghidra-mcp",
  "args": []
}
```

该进程把每个工具调用发送给守护进程。
如果守护进程没有运行，该进程会启动它。
该进程通过本地套接字连接守护进程。
在 Unix 上，套接字是私有的 Unix 域套接字。
在 Windows 上，套接字是命名管道。
该进程在工具调用之间复用此连接，以避免重复握手延迟。
如果守护进程停止，该进程会在下一次调用时重新连接。

要从源代码检出运行，请使用 `cargo run --` 作为命令。

### HTTP 服务器

要在前台运行守护进程，请使用以下命令：

```sh
ghidra-mcp --daemon
```

守护进程在一个监听器上提供以下端点：

| 端点 | 用途 |
| --- | --- |
| `http://127.0.0.1:18489/mcp` | 通过 Streamable HTTP 或旧式 SSE 提供 MCP。 |
| `/upload` | 二进制文件上传。 |
| `/ws/agent` | Ghidra 桥接的 WebSocket。 |

守护进程只接受回环地址。
要使用其他地址，请使用 `--listen`：

```sh
ghidra-mcp --daemon --listen 127.0.0.1:18490
```

使用 `--listen 127.0.0.1:0` 时，系统会选择一个空闲端口。
守护进程把地址写入运行时目录中的 `server.json` 和 `daemon.log`。

所有客户端断开连接后，守护进程继续运行。
要停止前台守护进程，请按 Ctrl-C。
在 Unix 上，`SIGINT`、`SIGTERM` 和 `SIGHUP` 也会停止它。
守护进程停止时，会关闭它的 Ghidra 会话。
您以后可以再次打开已保存的项目。

### 命令行工具

命令行工具使用与 MCP 相同的工具目录。

要在不启动守护进程的情况下列出工具，请使用以下命令：

```sh
ghidra-mcp tools
```

要通过守护进程调用一个工具，请使用以下命令：

```sh
ghidra-mcp call ghidra_session '{"operation":"list"}'
```

`call TOOL [JSON]` 接受一个 JSON 对象，默认值为 `{}`。
必要时，该命令会启动守护进程。
该命令以格式化的 JSON 输出 `structuredContent`。

| 结果 | 输出 | 退出码 |
| --- | --- | --- |
| 调用成功。 | 结果输出到 stdout。 | 0 |
| 调用失败。 | 错误输出到 stderr。 | 1 |
| 参数无效。 | 用法输出到 stderr。 | 2 |
| `--help` 或 `--version`。 | 文本输出到 stdout。 | 0 |

### 从远程客户端上传二进制文件

当客户端不在守护进程主机上时，请使用此步骤。

![远程上传流程](docs/img/remote_upload.svg)

1. 在客户端上，计算文件的 MD5 和字节大小。
2. 调用 `ghidra_upload` 工具：

   ```json
   {"operation":"prepare","md5":"0123456789abcdef0123456789abcdef","params":{"fileName":"program.bin","size":1024}}
   ```

   `fileName` 是显示名称，不能包含目录。
3. 读取结果。结果包含以下字段：
   - `method`：`POST`。
   - `url`：HTTP 调用返回绝对地址，例如 `https://host/ghidra/upload`。
     其他传输方式返回相对于 MCP URL 的 `upload`。
   - `headers`：一次性的 `Authorization: Bearer` 凭据和 `Content-Type: application/octet-stream`。
   - `expiresAt`：以 Unix 秒表示的过期时间。
4. 使用结果中的请求头，把文件作为原始请求体发送：

   ```sh
   curl -X POST 'https://host/ghidra/upload' \
     -H 'Authorization: Bearer <credential>' \
     -H 'Content-Type: application/octet-stream' \
     --data-binary @program.bin
   ```

5. 读取响应：
   - HTTP `200`：会话已就绪。
   - HTTP `202`：会话正在启动。请对返回的 `jobId` 使用 `ghidra_job wait`。

不需要另外调用 `ghidra_session open`。

> [!NOTE]
> - 上传内容直接写入磁盘，可以大于 MCP 请求的大小限制。守护进程接受 HTTP 分块传输。
> - 必须在 `ghidra_upload prepare` 之后十分钟内开始上传。此限制不适用于活动上传。
> - 请求在开始时使用凭据。上传失败后，请获取新的凭据。
> - 守护进程在保存二进制文件之前检查大小和 MD5。失败的上传不会留下文件，也不会创建会话。
> - 如果 Ghidra 没有启动，二进制文件仍然保存着。请使用 `ghidra_session open` 和 MD5 重试操作。
> - 反向代理必须以相同的前缀把 `/mcp` 和 `/upload` 都转发给守护进程。

服务器优先使用 `Forwarded` 中的主机和协议，其次使用 `X-Forwarded-Host` 和
`X-Forwarded-Proto`。`X-Forwarded-Prefix` 用于恢复代理移除的路径前缀。
服务器也可以使用路径以 `/mcp` 结尾的 HTTP 或 HTTPS 绝对 `Referer` 地址，
但不会把指向客户端页面的 Referer 当作服务器地址。
没有这些请求头时，使用 HTTP 请求地址。协议或路径前缀无效时，保留相对地址。
代理必须用正确的对外地址覆盖客户端提交的地址请求头。

## 与编码代理一起使用

编码代理把 `ghidra-mcp` 作为 stdio 服务器启动，或连接到 HTTP URL。
使用同一运行时目录的代理共享一个守护进程。

![逆向工程工作流](docs/img/reverse_engineering_flow.svg)

对于 Claude Code，请将可执行文件添加为本地 stdio 服务器：

```sh
claude mcp add --transport stdio --scope local ghidra-mcp -- /absolute/path/to/ghidra-mcp
```

要检查连接，请使用 `claude mcp get ghidra-mcp` 或 `/mcp` 面板。
状态必须为 `Status: ✓ Connected`。

在代理中请使用以下步骤：

1. 打开二进制文件：
   - 对于守护进程以前保存过的二进制文件，用 `{"operation":"open","md5":"..."}` 调用 `ghidra_session`。
   - 对于守护进程主机上的文件，用 `{"operation":"open","params":{"path":"..."}}` 调用 `ghidra_session`。守护进程计算 MD5 并保存二进制文件。
   - 对于远程客户端上的文件，请上传它（参见[从远程客户端上传二进制文件](#从远程客户端上传二进制文件)）。
2. 如果会话正在启动，请用 `{"operation":"wait","params":{"jobId":"...","timeoutMs":...}}` 调用 `ghidra_job` 等待。
   您可以用 `ghidra_job get` 监视作业。
3. 用 `ghidra_session get` 确认就绪状态。
4. 启动分析：用 `{"operation":"start","md5":"..."}` 调用 `ghidra_analysis`。
5. 用 `ghidra_job get` 或 `ghidra_job wait` 监视分析作业。
6. 使用桥接的领域工具，例如 `ghidra_program get`、`ghidra_function list` 和 `ghidra_data_type create`。
7. 用 `ghidra_program save` 保存分析结果和修改。会话保持打开。
8. 在使用会修改程序的操作之前，请获得用户的批准。

会话摘要只包含 `md5`、`fileName`、`status` 和 `connected`。
所有会话操作都使用 `md5`，没有单独的会话 ID。
`ghidra_session list` 是可选的。
对于守护进程不认识的 MD5，守护进程会提示您上传二进制文件。

## 配置

首次启动时，守护进程会在持久主目录中写入默认的 `config.toml`。
以下示例显示所有键及其默认值：

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

| 键 | 用途 |
| --- | --- |
| `ghidra.home` | Ghidra 安装目录。 |
| `ghidra.analyze_headless` | `analyzeHeadless` 的路径。 |
| `analysis.max_cpu` | `analyzeHeadless -max-cpu` 的值。 |
| `timeouts.process_spawn_timeout_sec` | 启动 Ghidra 进程的时间。 |
| `timeouts.analysis_import_timeout_sec` | 导入二进制文件的时间。也是 `ghidra_analysis start` 的默认等待时间。 |
| `timeouts.bridge_connect_timeout_sec` | 启动会话总时间的一部分。 |
| `timeouts.agent_ready_timeout_sec` | 桥接完成握手的时间。 |
| `timeouts.bridge_disconnect_grace_sec` | 桥接断开或会话关闭后，进程自行停止的时间。 |
| `timeouts.graceful_kill_timeout_sec` | 守护进程要求进程停止后，进程停止的时间。 |
| `timeouts.force_kill_timeout_sec` | 守护进程强制终止进程后，进程停止的时间。 |
| `timeouts.rpc_ms` | 一个桥接请求的时间，以毫秒为单位。 |
| `timeouts.daemon_start_timeout_sec` | 在代理或 CLI 模式中等待守护进程的时间。 |
| `timeouts.ipc_handshake_timeout_sec` | 代理与守护进程之间 IPC 握手的超时时间。 |

- `home` 或 `analyze_headless` 为空字符串时，效果与不设置相同。
- 守护进程忽略其他节和键。文件必须是有效的 TOML。
- Java 临时文件始终放在运行时目录的 `tmp/` 目录中。
- 守护进程不接受已删除的键 `ghidra.java_tmp_dir`、`ghidra.script_path` 和 `ghidra.bridge_script`。请从文件中删除它们。

## MCP 工具

`tools/list` 显示 18 个 MCP 工具：`ghidra_help`，以及每个领域一个工具。
领域和操作与桥接的 MCP 服务器相同。
本文用工具名加操作名表示一个操作，例如 `ghidra_session open`。

领域工具有以下参数：

- `operation`：必需。领域中的操作，例如 `list`。
- `md5`：操作所指定会话的 MD5。它从不放在 `params` 中。每个操作都有一个 md5 规则：`required`、`optional` 或 `absent`。
- `params`：操作的参数。默认值为 `{}`。

| 工具 | 操作 | 运行位置 |
| --- | --- | --- |
| `ghidra_session` | `open`、`list`、`get`、`close` | 守护进程。 |
| `ghidra_upload` | `prepare` | 守护进程。 |
| `ghidra_job` | `get`、`wait` | 守护进程。 |
| `ghidra_analysis` | `start`、`get` | `start`：守护进程，然后是桥接。`get`：桥接。 |
| `ghidra_bridge`、`ghidra_program`、`ghidra_address`、`ghidra_memory`、`ghidra_listing`、`ghidra_global_variable`、`ghidra_function`、`ghidra_decompilation`、`ghidra_symbol`、`ghidra_reference`、`ghidra_comment`、`ghidra_data_type`、`ghidra_batch` | 该领域的桥接方法。 | 会话的桥接。 |

桥接契约 `bridge/docs/asyncapi.yaml` 给出桥接方法、它们的模式和 `read_only` 效果。
守护进程只发送契约中的方法。
它不提供 `interface.get` 和 `session.shutdown`。要停止会话，请使用 `ghidra_session close`。
参数使用桥接的对象，例如 `selector`、`filter`、`page`、`patch` 和 `resource`。

`ghidra_function get` 和 `ghidra_comment upsert` 的示例：

```json
{"operation":"get","md5":"0123456789abcdef0123456789abcdef","params":{"selector":{"entry":"ram:00100000"}}}
{"operation":"upsert","md5":"0123456789abcdef0123456789abcdef","params":{"resource":{"address":"ram:00100000","type":"eol","text":"checked"}}}
```

`ghidra_help` 工具描述所有工具：

- `{}` 列出领域工具。
- `{"domain":"function"}` 列出一个领域的操作。
- `{"domain":"function","operation":"list"}` 显示一个操作的完整参数模式、md5 规则和效果。效果与桥接契约相同，例如 `read_only`、`mutates_program` 和 `destructive`。

如果 Ghidra 进程没有启动，会话进入 `error` 状态，它的启动作业进入 `failed` 状态。
使用 `wait=false` 时，`ghidra_session open` 立即返回。请使用 `ghidra_session get` 和 `ghidra_job get` 查看结果。
使用 `wait=true` 时，`ghidra_session open` 会等待并返回错误。

二进制文件的 MD5 标识每个会话。
守护进程通过有限状态机管理会话状态：

![会话生命周期](docs/img/session_lifecycle.svg)

当工具调用失败时，`structuredContent` 包含机器可读的 JSON-RPC 错误码：
- `-32602`（`invalid_argument`）：未知的工具，或无效或不存在的工具参数或操作参数。
- `-32001`（`session_lock_timeout`、`agent_timeout`、`request_in_flight`）：锁超时或请求冲突。
- `-32002`（`missing_target`）：未知的二进制 MD5、会话、作业 ID、领域或操作。
- `-32000`（`disconnected`、`shutting_down`）：已断开连接的桥接会话或守护进程关闭。
- `-32603`（`transaction_failed`、`bridge_internal`、`internal_error`）：Ghidra 事务失败或内部错误。
数据库事务失败返回错误码 `-32603`（`transaction_failed`）。
它们不会作为无效参数返回。

## 文件和目录

在 Unix 上，持久数据和运行时数据位于不同的位置：

```text
GHIDRA_MCP_HOME/                 # 默认：~/.ghidra-mcp
|-- config.toml
`-- projects/<md5>/
    |-- binary                  # 已保存的二进制文件，使用固定名称
    |-- binary.json             # 原始文件名
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

- 在 Linux 上，运行时基础目录是 `XDG_RUNTIME_DIR`。否则，它是系统的临时目录。
- 如果运行时基础目录包含隐藏段，守护进程改用 `/tmp`。Ghidra 不接受隐藏段。
- 运行时目录的权限为 `0700`。守护进程日志和锁文件的权限为 `0600`。
- Ghidra 无法打开隐藏目录中的项目。因此，守护进程把 `projects` 符号链接交给 Ghidra。项目文件保留在持久主目录中。
- 如果 `projects` 路径被其他对象占用，守护进程会报错停止，不会替换该对象。

在 Windows 上，默认布局为：

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

- `GHIDRA_MCP_HOME` 会移动配置和项目。运行时目录保留在 `%LOCALAPPDATA%\ghidra-mcp\run`。
- Ghidra 直接打开项目，不使用符号链接。
- 客户端通过命名管道连接。`server.json` 包含它的随机名称。只有所有者可以连接，远程客户端无法连接。

在所有平台上：

- 每个运行时目录运行一个守护进程，由文件锁保证。不使用 PID 文件。
- 每个运行时目录使用一个持久主目录。要更改 `GHIDRA_MCP_HOME`，请先停止守护进程并清空运行时目录。旧主目录中的项目仍然可用。
- 守护进程没有运行时，可以删除运行时目录。之后，使用 MD5 调用 `ghidra_session open` 会重新打开已保存的项目。
- 当 `project.gpr` 和 `project.rep` 存在时，守护进程重新打开项目。Ghidra 会重放它的恢复日志。
- 守护进程不会修改它不认识的项目目录，而是显示错误。
- 守护进程将所有日志文件（`daemon.log`、`stdout.log`、`stderr.log`）限制为 10 MiB。
- 超长日志行会被截断。转发器将超过 10 MiB 的行替换为 `[TRUNCATED_LOG_LINE]`。
- 当日志文件达到 10 MiB 时，守护进程轮转日志并保留最多 3 个备份（`.1`、`.2`、`.3`）。
- 守护进程自动将日志行中的敏感认证令牌替换为 `[REDACTED_TOKEN]`。
- 在 Windows 上，守护进程在重命名日志文件之前先关闭活动的写入句柄。
- 守护进程在打开大于 10 MiB 的 `daemon.log` 前先轮转该文件。

## 验证和发布

要执行与 CI 相同的检查，请使用以下命令：

```sh
cargo xtask ci
cargo xtask build --release --locked --bin ghidra-mcp
```

或者分别运行各项检查：

```sh
cargo xtask check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked
```

CI 在 macOS、Linux 和 Windows 上为 x86_64 和 ARM64 构建发布版可执行文件。
每次推送到 `main`、每个拉取请求和每次手动运行都会启动全部六个构建。
一个构建失败不会停止其他构建。
Windows 可执行文件静态链接 C 运行时。

release-please 根据 `main` 上的 Conventional Commits 设置版本：

- `fix:` 产生补丁版本。
- `feat:` 产生次要版本。
- `!` 或 `BREAKING CHANGE:` 产生主要版本。

release-please 会打开一个发布拉取请求。
该拉取请求更新工作区版本、`Cargo.lock`、`CHANGELOG.md` 和发布清单。
合并后，release-please 在固定提交上创建版本标签和发布草稿。
六个平台的构建及依赖审计均使用该提交。
检查全部通过后，CI 上传可执行文件、SHA-256 校验和及许可证文本。
然后 CI 公开发布草稿。
检查失败时，发布保持草稿状态。请重新运行失败的任务。
CI 使用默认的 `GITHUB_TOKEN`，不需要其他密钥。

> [!NOTE]
> - 仓库必须允许 GitHub Actions 创建拉取请求。
> - 由 `GITHUB_TOKEN` 创建的发布拉取请求，其 CI 运行需要维护者批准。请在合并前批准该运行。

## 故障排除

有关 Ghidra 查找、Java 21、套接字权限、内存和日志的操作手册，
请阅读[故障排除指南](docs/zh/troubleshooting.md)。

### 守护进程找不到 `analyzeHeadless`

- 设置 `GHIDRA_INSTALL_DIR` 或 `GHIDRA_HOME`。
- 或者，把 `analyzeHeadless` 或 `ghidraRun` 放到 `PATH` 上。

### 缺少桥接 JAR

- 确认 `ghidra-bridge.jar` 位于运行时目录中。
- 如果修改了桥接源代码，请再次运行 `cargo xtask build`。xtask 命令会重新构建并嵌入桥接。

### 守护进程无法启动

- 阅读运行时目录中的 `daemon.log`。
- 确认没有其他程序使用该 HTTP 地址。要让系统选择空闲端口，请使用 `--listen 127.0.0.1:0`。
- `daemon.lock` 阻止同一运行时目录中的第二个守护进程。守护进程运行时，请勿删除运行时文件。

## 文档

- [第一步](docs/zh/getting-started.md)：配置步骤和首次分析过程。
- [故障排除](docs/zh/troubleshooting.md)：查找、Java 21、权限、内存与日志的操作手册。
- [体系架构](docs/zh/architecture.md)：进程、请求流程、会话生命周期、并发、进程所有权和安全性。
- 每个模块和条目的 API 文档（英文）：`cargo doc --no-deps --document-private-items --open`。
- [安全策略](SECURITY.md)（英文）：部署和漏洞报告。
- [变更日志](CHANGELOG.md)（英文）。
- Java 桥接有自己的文档：[`bridge/README.zh-CN.md`](bridge/README.zh-CN.md)、[`bridge/docs/zh/protocol.md`](bridge/docs/zh/protocol.md)、[`bridge/docs/api.md`](bridge/docs/api.md) 和 [`bridge/docs/zh/development.md`](bridge/docs/zh/development.md)。

## 参与贡献

欢迎贡献。
[CONTRIBUTING.md](CONTRIBUTING.md)（英文）给出前提条件、代码和文本标准，以及扩展步骤。
[行为准则](CODE_OF_CONDUCT.md)（英文）适用于所有参与者。

Rust 代码位于 `src/` 中。
`xtask/` 目录包含自动化工具。
Java 桥接是一个 Git 子模块。
请使用 `--recurse-submodules` 克隆，或执行 `git submodule update --init --recursive`。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。
`bridge/` 中的 Java 桥接使用单独的许可证。请参阅 [`bridge/LICENSE`](bridge/LICENSE)。
