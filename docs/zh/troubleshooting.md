# 故障排除 (Troubleshooting)

[English](../troubleshooting.md) | [中文](troubleshooting.md) | [日本語](../ja/troubleshooting.md)

本操作手册帮助您诊断和解决 `ghidra-mcp` 的常见问题。

## 目录

- [1. 无头可执行文件查找](#1-无头可执行文件查找)
- [2. Java 21 环境配置](#2-java-21-环境配置)
- [3. 套接字与管道权限](#3-套接字与管道权限)
- [4. 内存限制与大文件配置](#4-内存限制与大文件配置)
- [5. 日志诊断与错误代码](#5-日志诊断与错误代码)

## 1. 无头可执行文件查找

### 症状

- 守护进程在启动阶段以状态码 `1` 退出。
- stderr 和 `daemon.log` 报告找不到 `analyzeHeadless`，或该文件不可执行。

### 查找优先级

守护进程按以下顺序查找 `analyzeHeadless`：

1. `config.toml` 中的 `[ghidra].analyze_headless`。
2. `config.toml` 中的 `[ghidra].home`，或者 `GHIDRA_INSTALL_DIR` / `GHIDRA_HOME` 环境变量。
3. 系统 `PATH` 上的 `analyzeHeadless`。
4. 系统 `PATH` 上的 `ghidraRun`。
5. 标准目录：`/Applications/ghidra*`、`/opt/homebrew/Caskroom/ghidra/*`、`~/Applications`、`~`、`~/opt`。

### 解决方案

在环境中或 MCP 客户端设置中设置 `GHIDRA_INSTALL_DIR`：

```sh
export GHIDRA_INSTALL_DIR="/path/to/ghidra_12.1.4_PUBLIC"
```

在 Windows 上：

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.1.4_PUBLIC"
```

或者，在持久主目录的 `config.toml` 中进行配置：

```toml
[ghidra]
home = "/path/to/ghidra_12.1.4_PUBLIC"
```

## 2. Java 21 环境配置

### 症状

- 会话启动时 Ghidra 立即崩溃。
- 日志显示：`UnsupportedClassVersionError: ... class file version 65.0`。

### 原因

Ghidra 11 或更高版本和嵌入式桥接运行时需要 Java 21 JDK。
较旧的 Java 版本无法运行这些类文件。

### 解决方案

1. 验证您的 Java 版本：

   ```sh
   java -version
   ```

2. 安装 OpenJDK 21 或 Eclipse Temurin 21。
3. 设置 `JAVA_HOME` 指向 Java 21 安装路径：

   ```sh
   export JAVA_HOME="/usr/lib/jvm/java-21-openjdk"
   ```

4. 重启您的 MCP 客户端或守护进程。

## 3. 套接字与管道权限

### 症状

- MCP 客户端失败并报错 `ConnectionRefused` 或 `PermissionDenied`。
- 代理无法连接到守护进程。

### Unix 域套接字

守护进程将 Unix 套接字保存在 `<runtime_dir>/daemon.sock` 中。
运行时目录要求 `0700` 权限模式。
套接字文件要求 `0600` 权限模式。
客户端进程和守护进程必须在相同的用户 UID 下运行。

检查权限：

```sh
ls -ld /run/user/$UID/ghidra-mcp-*
ls -l /run/user/$UID/ghidra-mcp-*/daemon.sock
```

必要时修复目录权限：

```sh
chmod 0700 /run/user/$UID/ghidra-mcp-*
```

### Windows 命名管道

守护进程创建命名管道 `\\.\pipe\ghidra-mcp-<uuid>`。
该管道强制执行仅所有者访问的 DACL 描述符 `D:P(A;;GA;;;OW)`。
MCP 客户端必须在同一个 Windows 用户帐户下运行。
没有管道访问权限的沙箱环境或容器进程无法连接。

## 4. 内存限制与大文件配置

### 症状

- Ghidra 分析崩溃并报错 `java.lang.OutOfMemoryError`。
- 大于 50 MB 的二进制文件或复杂固件导致内存使用量过高。

### JVM 堆内存配置

通过 `JAVA_TOOL_OPTIONS` 增加 JVM 堆内存限制：

```sh
export JAVA_TOOL_OPTIONS="-Xmx8G -Xms2G"
```

在 Windows 上：

```powershell
$env:JAVA_TOOL_OPTIONS = "-Xmx8G -Xms2G"
```

### CPU 并发限制

在 `config.toml` 中限制用于分析的 CPU 核心数：

```toml
[analysis]
max_cpu = 2
```

较低的线程数可减少并行分析期间的峰值内存使用量。

### 日志限制与截断

守护进程将所有日志文件（`daemon.log`、`stdout.log`、`stderr.log`）限制为 10 MiB。
当日志文件达到 10 MiB 时，守护进程会轮转并保留最多 3 个备份（`.1`、`.2`、`.3`）。
转发器会将大于 10 MiB 的单行日志替换为 `[TRUNCATED_LOG_LINE]`。

## 5. 日志诊断与错误代码

### 日志位置

检查这些日志文件以诊断问题：

- 守护进程日志：`<runtime_dir>/daemon.log`
- 子进程标准输出：`<runtime_dir>/logs/<md5>/stdout.log`
- 子进程标准错误：`<runtime_dir>/logs/<md5>/stderr.log`

守护进程将日志中的敏感 bearer 令牌替换为 `[REDACTED_TOKEN]`。

### JSON-RPC 错误代码

工具调用在 `structuredContent` 中返回标准 JSON-RPC 2.0 错误代码：

| 代码 | 名称 | 原因 | 解决方案 |
| --- | --- | --- | --- |
| `-32602` | `invalid_argument` | 未知的工具，或工具参数或操作参数不存在或无效。 | 使用 `ghidra_help` 检查参数。 |
| `-32001` | `session_lock_timeout` | 会话锁超时或请求冲突。 | 等待进行中的操作完成。 |
| `-32002` | `missing_target` | 未找到目标二进制文件、会话、作业 ID、领域或操作。 | 先打开会话或上传二进制文件。 |
| `-32000` | `disconnected` | 桥接已断开或守护进程正在执行关闭操作。 | 使用 `ghidra_session open` 重新打开会话。 |
| `-32603` | `transaction_failed` | 内部数据库事务或桥接错误。 | 检查子进程日志。 |
