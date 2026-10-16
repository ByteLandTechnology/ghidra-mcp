# 第一步 (First Steps)

[English](../getting-started.md) | [中文](getting-started.md) | [日本語](../ja/getting-started.md)

本指南帮助您配置 `ghidra-mcp` 并连接您的 AI 编码代理。
`ghidra-mcp` 作为 Ghidra 的模型上下文协议 (MCP) 服务器运行。
它提供无头二进制分析、反编译和符号检查功能。

## 目录

- [前提条件](#前提条件)
- [安装](#安装)
- [客户端配置](#客户端配置)
  - [Claude Desktop](#claude-desktop)
  - [Cursor](#cursor)
  - [Zed](#zed)
  - [Windsurf](#windsurf)
  - [Claude Code](#claude-code)
- [首次分析过程](#首次分析过程)
  - [1. 打开二进制会话](#1-打开二进制会话)
  - [2. 启动后台分析](#2-启动后台分析)
  - [3. 轮询作业进度](#3-轮询作业进度)
  - [4. 检查符号与反编译](#4-检查符号与反编译)
  - [5. 保存更改与关闭](#5-保存更改与关闭)
- [后续步骤](#后续步骤)

## 前提条件

在使用 `ghidra-mcp` 之前，请安装以下组件：

- Linux、macOS 或 Windows。
- Java 21 JDK。
- 包含 `analyzeHeadless`（Windows 上为 `analyzeHeadless.bat`）的 Ghidra 12.1 或更高版本。

## 安装

### 预构建二进制文件

从 [GitHub Releases](https://github.com/ByteLandTechnology/ghidra-mcp/releases) 下载适合您平台的二进制文件。

| 平台 | x86_64 | ARM64 |
| --- | --- | --- |
| macOS | `ghidra-mcp-macos-x86_64` | `ghidra-mcp-macos-arm64` |
| Linux | `ghidra-mcp-linux-x86_64` | `ghidra-mcp-linux-arm64` |
| Windows | `ghidra-mcp-windows-x86_64.exe` | `ghidra-mcp-windows-arm64.exe` |

1. 将下载的文件重命名为 `ghidra-mcp`（Windows 上为 `ghidra-mcp.exe`）。
2. 在 Linux 和 macOS 上，赋予二进制文件可执行权限：

   ```sh
   chmod +x ghidra-mcp
   ```

3. 设置 `GHIDRA_INSTALL_DIR` 指向您的 Ghidra 安装目录。

### 从源代码构建

要从源代码构建，请使用以下步骤：

1. 安装 Rust 工具链。
2. 克隆仓库及其子模块：

   ```sh
   git clone --recurse-submodules https://github.com/ByteLandTechnology/ghidra-mcp.git
   ```

3. 切换到仓库目录：

   ```sh
   cd ghidra-mcp
   ```

4. 构建发布版可执行文件：

   ```sh
   cargo xtask build --release --locked --bin ghidra-mcp
   ```

构建过程会将 Java 桥接运行时嵌入到编译后的二进制文件中。
输出的二进制文件位于 `target/release/ghidra-mcp`（Windows 上为 `ghidra-mcp.exe`）。

## 客户端配置

配置您的 MCP 客户端以连接到 `ghidra-mcp`。

### Claude Desktop

将 `ghidra` 添加到您的 `claude_desktop_config.json` 文件中。

文件路径：
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

配置代码片段：

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

将 `ghidra-mcp` 添加到工作区中的 `.cursor/mcp.json` 或全局设置中。

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

在 `~/.config/zed/settings.json` 的 `context_servers` 下添加 `ghidra`。

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

将 `ghidra` 添加到 `~/.codeium/windsurf/mcp_config.json`。

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

将 `ghidra-mcp` 注册为本地 stdio MCP 服务器：

```sh
gemini mcp add --transport stdio --scope project ghidra-mcp /path/to/ghidra-mcp
```

要连接已经运行的守护进程，请使用 Streamable HTTP：

```sh
gemini mcp add --transport http --scope project \
  ghidra-mcp http://127.0.0.1:18489/mcp
```

旧客户端可以在同一 URL 上使用 SSE：

```sh
gemini mcp add --transport sse --scope project \
  ghidra-mcp http://127.0.0.1:18489/mcp
```

新配置请使用 `http` 传输。仅在客户端需要旧式 SSE 传输时使用 `sse`。

### Claude Code

将 `ghidra-mcp` 注册为本地 stdio MCP 服务器：

```sh
claude mcp add --transport stdio --scope local ghidra-mcp -- /path/to/ghidra-mcp
```

验证服务器连接状态：

```sh
claude mcp get ghidra-mcp
```

## 首次分析过程

守护进程提供 `ghidra_help`，并为每个领域提供一个 MCP 工具。
每个领域工具接受一个 `operation` 及其 `params`。
指定一个会话的操作还接受该会话的 `md5`。
本文用工具名加操作名表示一个操作，例如 `ghidra_session open`。

### 1. 打开二进制会话

使用 `ghidra_session` 打开本地二进制文件：

```json
{
  "operation": "open",
  "params": { "path": "/path/to/target_binary" }
}
```

守护进程计算 MD5 哈希并将二进制文件复制到持久存储中。
调用返回一个启动作业记录。
使用 `ghidra_session` 检查会话状态：

```json
{
  "operation": "get",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

当会话就绪时，`status` 字段显示 `ready`。

### 2. 启动后台分析

使用 `ghidra_analysis` 在打开的二进制文件上启动自动分析：

```json
{
  "operation": "start",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

调用返回状态为 `status: "running"` 的作业记录。

### 3. 轮询作业进度

使用 `ghidra_job` 以 500 毫秒间隔轮询作业状态：

```json
{
  "operation": "get",
  "params": { "jobId": "job-12345" }
}
```

或者，阻塞等待作业完成：

```json
{
  "operation": "wait",
  "params": { "jobId": "job-12345", "timeoutMs": 60000 }
}
```

当分析完成时，作业记录显示 `status: "completed"`。

### 4. 检查符号与反编译

使用 `ghidra_function` 列出二进制文件中的函数：

```json
{
  "operation": "list",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

使用 `ghidra_symbol` 检查符号：

```json
{
  "operation": "list",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

使用 `ghidra_decompilation` 在入口点反编译函数：

```json
{
  "operation": "get",
  "md5": "0123456789abcdef0123456789abcdef",
  "params": { "selector": { "entry": "ram:140001000" } }
}
```

桥接返回结构化 C 伪代码、函数签名和局部变量。
要查看一个操作的参数，请使用 `domain` 和 `operation` 调用 `ghidra_help`。

### 5. 保存更改与关闭

使用 `ghidra_program` 将程序更改保存到 Ghidra 项目中：

```json
{
  "operation": "save",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

使用 `ghidra_session` 关闭活动会话：

```json
{
  "operation": "close",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

## 后续步骤

- 阅读[故障排除](troubleshooting.md)获取常见问题的解决方法。
- 阅读[体系架构](architecture.md)了解深入的系统内部设计。
