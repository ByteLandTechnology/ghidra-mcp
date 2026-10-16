# 体系架构 (Architecture)

[English](../architecture.md) | [中文](architecture.md) | [日本語](../ja/architecture.md)

本文档描述 `ghidra-mcp` 的结构。
它描述进程、请求流程，以及保持共享状态正确的规则。
本文档面向贡献者。
[README.zh-CN.md](../../README.zh-CN.md) 描述使用方法。[第一步](getting-started.md) 提供配置步骤。[故障排除](troubleshooting.md) 涵盖常见问题。
## 目录

- [进程](#进程)
- [源代码布局](#源代码布局)
- [请求流程](#请求流程)
- [会话生命周期](#会话生命周期)
- [并发](#并发)
- [进程所有权](#进程所有权)
- [磁盘上的文件](#磁盘上的文件)
- [接口](#接口)
- [安全模型](#安全模型)
- [扩展系统](#扩展系统)

## 进程

![体系架构](../img/architecture.svg)

一个可执行文件承担所有角色：

| 角色 | 启动者 | 状态 | 说明 |
|---|---|---|---|
| **守护进程**（`--daemon`） | 第一次代理调用或 CLI 调用，或者用户。 | 全部状态。 | 每个运行时目录运行一个守护进程，由文件锁保证。守护进程一直运行，直到您停止它。 |
| **Stdio 代理**（无参数） | MCP 客户端。 | 无状态。 | 代理把每个工具调用发送给守护进程。必要时，它会启动守护进程。 |
| **CLI**（`tools`、`call`） | 用户。 | 无状态。 | `tools` 不连接守护进程。`call` 通过守护进程执行一次调用。 |
| **Ghidra**（`analyzeHeadless`） | 守护进程，每个打开的会话一个。 | 分析结果。 | Ghidra 把桥接作为后置脚本运行。 |

客户端通过**本地套接字**连接守护进程。
在 Unix 上，本地套接字是 Unix 域套接字。在 Windows 上，它是命名管道。
守护进程把套接字的地址写入运行时目录中的 `server.json`。
如果没有守护进程响应，客户端会启动一个守护进程。
客户端以分离进程的方式启动新的守护进程。因此，客户端停止后守护进程继续运行。

**桥接**是 `bridge/` 子模块中的 Java 程序。
`cargo xtask build` 命令用 Gradle 构建桥接。
然后它把桥接 JAR 和启动脚本 `Bridge.java` 嵌入可执行文件。
每次启动之前，守护进程把这两个文件写入运行时目录。
它把它们交给 `analyzeHeadless -postScript`。
然后桥接通过 WebSocket 连接守护进程，并提供分析 API。

## 源代码布局

所有 Rust 应用程序代码都在 [`src/`](../../src) 中。
一个模块只使用它下方各层中的模块：

![源码分层](../img/source_layout.svg)

| 模块 | 职责 |
|---|---|
| `cli` | 命令行参数和三种运行模式。 |
| `daemon` | 监听器、文件锁、`server.json`、分离启动、代理连接复用和关闭。 |
| `mcp` | MCP 处理程序。它在守护进程中运行调用，或从代理把调用发送给守护进程。 |
| `mcp_http` | Streamable HTTP、旧式 SSE 会话、CORS 和 HTTP 兼容层。 |
| `upload` | 上传凭据和 `POST /upload` 端点。 |
| `tools` | `ghidra` 工具：本地命令表、分派、目录和 `help`。 |
| `session` | 会话的打开、启动、等待、重新启动、调用和关闭。 |
| `analysis` | 作为后台作业的自动分析。 |
| `project` | 已保存的二进制文件和 Ghidra 项目的准备。 |
| `bridge` | 桥接契约、嵌入的运行时、WebSocket 和单个请求。 |
| `jsonrpc` | 桥接 WebSocket 的严格 JSON-RPC 2.0 编解码器。 |
| `state` | 共享状态：每个会话一个条目，以及作业。 |
| `model` | 会话、作业和响应记录，以及会话状态机。 |
| `error` | 类型化领域错误（`DomainError`）与 JSON-RPC 协议错误码。 |
| `config`、`paths` | `config.toml`、持久主目录和运行时目录。 |
| `process` | 子进程、日志轮转（`RollingLogWriter`）、令牌脱敏和完整进程树停止。 |
| `ghidra`、`java_path` | 查找 `analyzeHeadless`，以及面向 Java 的路径转换。 |

要阅读每个模块和条目的 API 文档（英文），请使用 `cargo doc --document-private-items --open`。

## 请求流程

### 一次工具调用

![工具调用流程](../img/tool_call.svg)

所有命令都通过 MCP 工具 `ghidra`。`command` 参数选择命令。
`tools::dispatch` 根据命令的模式验证参数。
然后它执行以下操作之一：

- 运行 `LOCAL_COMMANDS` 中的**本地命令**：帮助、会话、作业、上传和分析。
- 把桥接契约 `bridge/docs/asyncapi.yaml` 中的**桥接方法**发送给桥接。

当桥接返回错误时，工具调用失败。失败的结果仍然包含结构化响应。
MCP 处理器将错误映射为类型化 `DomainError` 变体与 JSON-RPC 错误码（`-32602`、`-32001`、`-32002`、`-32000`、`-32603`）。
桥接将数据库事务失败（HTTP 500 `transaction_failed`）与客户端参数错误（HTTP 400 `invalid_request`）严格区分。

### 打开二进制文件

`session.open` 接受守护进程主机上的 `path`，或守护进程以前保存过的二进制文件的 `md5`。
对于路径，守护进程计算 MD5，并把文件复制到持久主目录。
之后的调用只需要 MD5。
守护进程重用已连接的会话，或加入正在进行的启动，或开始新的启动。
[会话生命周期](#会话生命周期)描述启动过程。
`session.open` 立即返回启动作业。如果客户端设置了 `wait`，它会等待该作业。

### 上传二进制文件

![上传流程](../img/remote_upload.svg)

客户端只能使用凭据一次。
请求在守护进程读取第一个字节之前使用凭据。
客户端必须在 `upload.prepare` 之后十分钟内开始上传。
守护进程不会停止活动上传。

### 关闭

以下事件会停止守护进程：Ctrl-C、`SIGTERM`、`SIGHUP`，以及对应的 Windows 控制台事件。
随后守护进程执行以下步骤：

1. 拒绝新的工作。
2. 停止它的监听器。
3. 停止所有 Ghidra 进程，如[进程所有权](#进程所有权)所述。
4. 关闭所有桥接连接。
5. 为它的服务器提供短暂的完成时间。

会话保留它们的运行时快照。下次启动后，它们处于 `stale` 状态。

## 会话生命周期

二进制文件的 MD5 标识一个会话。
会话具有以下状态之一（`model::SessionStatus`）：

![会话生命周期](../img/session_lifecycle.svg)

每个状态转换都是 `SessionRecord` 的一个 `mark_*` 方法。
因此，每个转换的规则都集中在一处。

一次启动有四个步骤：

1. **`begin_launch`** 准备项目并停止之前的进程。
   它保存一条带有新的 256 位桥接凭据的 `launching` 记录。
   它还创建启动作业。从这时起，该作业拥有会话。
2. **`launch_process`** 以桥接作为后置脚本启动 `analyzeHeadless`。
   它把会话设置为 `starting`。
3. 桥接连接并发送 `ghidra.ready`。
   **`bridge::handshake`** 检查凭据并挂接连接。
   它把会话设置为 `ready`。
4. **`wait_ready`** 看到 `ready` 后完成启动作业。
   如果进程过早停止、会话失败或启动时间过长，该作业失败。

每个步骤首先确认它的启动作业或凭据仍然拥有会话。
较新的启动可以替换一次启动，客户端也可以关闭会话。
在这些情况下，旧的步骤停止，不会修改较新的状态。

下一条命令会重新启动处于 `disconnected` 或 `stale` 状态的会话。
客户端不会察觉这次重新启动。

## 并发

守护进程是一个多线程的 Tokio 程序。
`state.rs` 中的三种机制保持状态正确：

- **生命周期锁**（`McpState::lifecycle_lock`，异步）使会话生命周期转换按顺序进行。
  这些转换是：打开、启动、握手、断开和关闭。
  任务可以跨 await 持有该锁，例如在进程停止期间。
- **状态互斥锁**保护会话映射和作业映射。
  任务只在不会阻塞的短代码段中持有它们，从不跨 await 持有。
  因此，大多数状态方法是同步的。
- **通知器**（`McpState::notify`）在每次变化后唤醒所有等待者。
  每个等待者会再次检查它的条件。因此，不必要的唤醒不会造成损害。
  启动等待还会每秒检查一次进程，以发现已停止的进程。

每个会话同一时间最多有一个桥接请求。
同时发出的第二个请求会以 `session already has a request in flight` 失败。
只有发送请求的连接才能应答该请求。守护进程会忽略来自被替换桥接的应答。
当桥接断开时，它未完成的请求会收到 `BRIDGE_DISCONNECTED` 错误。

## 进程所有权

`analyzeHeadless` 是一个启动 JVM 的脚本。
因此，守护进程停止的是完整的进程树，而不只是一个进程（`process.rs`）：

- **Unix。** 子进程是一个新进程组的组长。
  守护进程向这个进程组发送停止信号。
  如果守护进程停止，内核会关闭它的连接。`SIGKILL` 也会产生此结果。
  桥接检测到关闭的连接。
  如果桥接未检测到连接关闭，发往守护进程的保活 ping 会失败。
  桥接每 5 秒发送一次此 ping。

  然后，它取消活动分析并保存程序。
  Ghidra 退出。
  守护进程以 `exit_deadline_sec=120` 启动桥接。如果会话结束后 2 分钟内 Ghidra 没有退出，桥接会强制停止 JVM，但不会在保存期间这样做。
  没有其他进程监视守护进程。
- **Windows。** 守护进程以挂起状态启动子进程。
  它把该进程放入一个作业对象。
  然后它恢复该进程。
  当作业对象的最后一个句柄关闭时，作业对象会结束其中的所有进程。只有守护进程持有该句柄。

要停止会话，守护进程执行以下步骤：

1. 等待进程自行停止。只在桥接断开或正常关闭之后等待。
2. 要求进程树终止。
3. 强制结束进程树。

`config.toml` 在 `[timeouts]` 中设置每个步骤的时间限制。

子进程日志由 `RollingLogWriter` 管理：
- 活动日志文件（`stdout.log`、`stderr.log`、`daemon.log`）限制为 10 MiB。
- 超长日志行会被截断。转发器将超过 10 MiB 的行替换为 `[TRUNCATED_LOG_LINE]`。
- 当日志达到 10 MiB 时，进行轮转并保留最多 3 个备份世代（`.1`、`.2`、`.3`）。
- 敏感的 Bearer 认证令牌在行边界被替换脱敏为 `[REDACTED_TOKEN]`。
- 在 Windows 上，守护进程在重命名日志文件前关闭活动文件句柄。
- 如果 `daemon.log` 大于 10 MiB，守护进程会在打开该文件前轮转它。

## 磁盘上的文件

| 位置 | 内容 | 生存期 |
|---|---|---|
| **持久主目录**（`GHIDRA_MCP_HOME`，默认 `~/.ghidra-mcp` 或 `%LOCALAPPDATA%\ghidra-mcp`） | `config.toml`，以及 `projects/<md5>/`，其中包含 `binary`、`binary.json`、`binary.lock`、`ghidra/` 中的 Ghidra 项目和 `recovery-backups/` 中保留的崩溃恢复备份。 | 保留。 |
| **运行时目录**（系统运行时目录或临时目录中的 `ghidra-mcp-<uid>`，或 `%LOCALAPPDATA%\ghidra-mcp\run`） | `daemon.lock`、`daemon.log`、`daemon.sock`（Unix）、`server.json`、`sessions/<md5>/session.json`、`logs/<md5>/`、`tmp/`、桥接文件，以及 Unix 上的 `projects` 链接。 | 可以删除。 |

发布程序在目标目录内暂存文件。
它同步文件，再原子重命名文件。
Unix 还同步目录项。
Windows 对发布的文件请求 write-through 移动。
`binary.lock` 的独占锁覆盖二进制验证、发布和 `binary.json` 完成标记的发布。
读取取得同一文件的共享锁，等待发布完成。
写入失败只清理本次临时文件。
再次导入可以完成缺少元数据的已发布二进制文件。

守护进程保留无法识别的非空 Ghidra 工程，并停止打开操作。
守护进程用不带 `-process` 的 `OpenSavedProject.java` 打开已保存的工程。
因此，脚本控制首次打开程序并启用崩溃恢复。
检测到恢复快照后，脚本先将 `.gpr` 和 `.rep` 复制到唯一的 `recovery-backups/` 子目录。
脚本同步并发布副本后打开程序。
备份失败会停止打开操作。
脚本在桥接启动前保存恢复的更改。
恢复成功后仍保留备份。
守护进程不使用带有 `.pending-` 前缀的备份。

Ghidra 不接受包含隐藏段的项目路径。但默认主目录是一个隐藏目录。
因此，在 Unix 上，守护进程把**项目启动别名** `<runtime>/projects` 交给 Ghidra。
该别名是指向持久主目录中 `projects/` 目录的符号链接。

## 接口

| 接口 | 格式 | 契约 |
|---|---|---|
| MCP 工具 `ghidra` | 通过 stdio、本地套接字、Streamable HTTP 或旧式 SSE 的 MCP。 | `tools::LOCAL_COMMANDS` 和桥接契约中的命令。`help` 描述它们。 |
| 桥接 WebSocket `/ws/agent` | 严格的 JSON-RPC 2.0（`jsonrpc.rs`）。 | 桥接构建生成的 `bridge/docs/asyncapi.yaml`。 |
| 上传 `POST /upload` | 带 bearer 凭据的原始字节。 | `upload.prepare` 的结果。 |
| `server.json` | 包含 `pid`、`mcpUrl`、`bridgeWsUrl` 和 `localSocket` 的 JSON。 | 本地客户端读取它。 |
| `config.toml` | TOML。 | README 和 `config.rs`。 |
| 错误信封 | MCP `structured_content` 内的 JSON。 | 标准 JSON-RPC 错误码（`-32602` 至 `-32603`）与机器可读错误变体。 |

MCP 工具定义、命令模式、帮助输出和响应格式都是公共契约。
只能在有意的变更中修改它们。
请在变更日志中记录该变更。

## 安全模型

守护进程为本地用户及其运行的分析工具提供服务。
不要让其他主机访问它。

- **监听器。** 守护进程只接受回环地址。
  对 `/mcp` 或 `/upload` 的请求必须带有监听器的 Host。
  `/mcp` 接受任意有效的 HTTP 或 HTTPS Origin，并返回 CORS 请求头。
  `/upload` 只接受监听器的 Origin。
- **本地套接字。** 在 Unix 上，套接字位于私有的运行时目录中。
  在 Windows 上，它是一个随机命名的命名管道。它的访问列表只允许所有者连接，并拒绝远程客户端。
- **运行时目录。** 每次启动时，守护进程都会确认该目录是真实的目录。
  该目录必须属于当前用户，并且权限必须为 `0700`。
  因此，其他用户无法读取其中的文件，也无法在其中放置文件。
- **桥接凭据。** 凭据是一个随机的 256 位令牌。
  守护进程只在 `Authorization` 请求头中发送它，从不把它写入磁盘。
  守护进程会把它从 Ghidra 日志中移除。
  会话关闭或守护进程重启后，该凭据失效。
- **上传凭据。** 客户端只能使用一次凭据，且只针对一个 MD5、一个文件名和一个大小。
  守护进程在保存字节之前检查它们。
  守护进程拒绝上传后，会读取并丢弃剩余的字节，最多 1 GiB、30 秒。
  因此，先发送完整请求体再读取响应的客户端也能收到错误。
- **发给客户端的消息。** 错误消息和摘要不包含绝对路径或凭据。

[SECURITY.md](../../SECURITY.md)（英文）说明如何报告漏洞。

## 扩展系统

- **本地命令。** 在 `src/tools.rs` 的 `LOCAL_COMMANDS` 中添加一个条目。
  提供它的名称、描述、输入模式、修改标志和处理程序。
  使用 `parse` 把它的参数读入一个 `Deserialize` 结构体。
  之后 `help` 和验证会包含该命令。
- **桥接方法。** 在桥接中添加该方法。
  添加方法后重新生成契约。
  守护进程在编译时读取契约，并原样提供该方法。
- **会话状态或转换。** 在 `model.rs` 中为 `SessionRecord` 添加一个 `mark_*` 方法。
  在持有生命周期锁时调用它。
- **长时间操作。** 用 `McpState::insert_job` 创建作业。
  在任务中完成工作。
  用 `McpState::finish_job` 完成作业。
  返回 `McpState::await_job` 的结果。
  这样调用方可以选择是否等待。
- **配置值。** 在 `config.rs` 的相应节中添加一个字段。
  为它提供默认值和文档注释。
  在 README 中记录它。
