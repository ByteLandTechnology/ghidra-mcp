# 最初の手順 (First Steps)

[English](../getting-started.md) | [中文](../zh/getting-started.md) | [日本語](getting-started.md)

このガイドは `ghidra-mcp` の設定と AI コーディングエージェントへの接続を案内します。
`ghidra-mcp` は Ghidra の Model Context Protocol (MCP) サーバーとして動作します。
ヘッドレスなバイナリ解析、逆コンパイル、およびシンボル検査機能を提供します。

## 目次

- [前提条件](#前提条件)
- [インストール](#インストール)
- [クライアント設定](#クライアント設定)
  - [Claude Desktop](#claude-desktop)
  - [Cursor](#cursor)
  - [Zed](#zed)
  - [Windsurf](#windsurf)
  - [Claude Code](#claude-code)
- [初回解析手順](#初回解析手順)
  - [1. バイナリセッションを開く](#1-バイナリセッションを開く)
  - [2. バックグラウンド解析を開始する](#2-バックグラウンド解析を開始する)
  - [3. ジョブの進捗をポーリングする](#3-ジョブの進捗をポーリングする)
  - [4. シンボル検査と逆コンパイル](#4-シンボル検査と逆コンパイル)
  - [5. 変更の保存と終了](#5-変更の保存と終了)
- [次のステップ](#次のステップ)

## 前提条件

`ghidra-mcp` を使用する前に、以下のコンポーネントをインストールしてください：

- Linux、macOS、または Windows。
- Java 21 JDK。
- `analyzeHeadless`（Windows では `analyzeHeadless.bat`）を含む Ghidra 12.1 以降。

## インストール

### ビルド済みバイナリ

[GitHub Releases](https://github.com/ByteLandTechnology/ghidra-mcp/releases) からお使いのプラットフォーム用のバイナリをダウンロードします。

| プラットフォーム | x86_64 | ARM64 |
| --- | --- | --- |
| macOS | `ghidra-mcp-macos-x86_64` | `ghidra-mcp-macos-arm64` |
| Linux | `ghidra-mcp-linux-x86_64` | `ghidra-mcp-linux-arm64` |
| Windows | `ghidra-mcp-windows-x86_64.exe` | `ghidra-mcp-windows-arm64.exe` |

1. ダウンロードしたファイルを `ghidra-mcp`（Windows では `ghidra-mcp.exe`）に名前変更します。
2. Linux および macOS では、バイナリを実行可能にします：

   ```sh
   chmod +x ghidra-mcp
   ```

3. `GHIDRA_INSTALL_DIR` を Ghidra インストールディレクトリに設定します。

### ソースからのビルド

ソースからビルドするには、次の手順を使用します：

1. Rust ツールチェーンをインストールします。
2. リポジトリとサブモジュールをクローンします：

   ```sh
   git clone --recurse-submodules https://github.com/ByteLandTechnology/ghidra-mcp.git
   ```

3. リポジトリディレクトリに移動します：

   ```sh
   cd ghidra-mcp
   ```

4. リリース実行ファイルをビルドします：

   ```sh
   cargo xtask build --release --locked --bin ghidra-mcp
   ```

ビルドプロセスにより、Java ブリッジランタイムがコンパイル済みバイナリに埋め込まれます。
生成されるバイナリは `target/release/ghidra-mcp`（Windows では `ghidra-mcp.exe`）です。

## クライアント設定

`ghidra-mcp` に接続するように MCP クライアントを設定します。

### Claude Desktop

`claude_desktop_config.json` ファイルに `ghidra` を追加します。

ファイルパス：
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

設定スニペット：

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

ワークスペースの `.cursor/mcp.json` またはグローバル設定に `ghidra-mcp` を追加します。

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

`~/.config/zed/settings.json` の `context_servers` に `ghidra` を追加します。

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

`~/.codeium/windsurf/mcp_config.json` に `ghidra` を追加します。

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

`ghidra-mcp` をローカル stdio MCP サーバーとして登録します：

```sh
gemini mcp add --transport stdio --scope project ghidra-mcp /path/to/ghidra-mcp
```

すでに実行中のデーモンには Streamable HTTP で接続します：

```sh
gemini mcp add --transport http --scope project \
  ghidra-mcp http://127.0.0.1:18489/mcp
```

旧式クライアントは同じ URL で SSE を使用できます：

```sh
gemini mcp add --transport sse --scope project \
  ghidra-mcp http://127.0.0.1:18489/mcp
```

新しい設定では `http` トランスポートを使用してください。クライアントが旧式 SSE
トランスポートを必要とする場合にのみ `sse` を使用します。

### Claude Code

`ghidra-mcp` をローカル stdio MCP サーバーとして登録します：

```sh
claude mcp add --transport stdio --scope local ghidra-mcp -- /path/to/ghidra-mcp
```

サーバーの接続状態を確認します：

```sh
claude mcp get ghidra-mcp
```

## 初回解析手順

すべての操作は `ghidra` という単一の MCP ツールを使用します。
`command` パラメータで実行するアクションを選択します。

### 1. バイナリセッションを開く

ローカルのバイナリファイルを開きます：

```json
{
  "command": "session.open",
  "path": "/path/to/target_binary"
}
```

デーモンは MD5 ハッシュを計算し、バイナリを永続ストレージにコピーします。
呼び出しは起動ジョブのレコードを返します。
セッションの状態を確認します：

```json
{
  "command": "session.get",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

セッションの準備が完了すると、`status` フィールドに `ready` が表示されます。

### 2. バックグラウンド解析を開始する

開いたバイナリの自動解析を開始します：

```json
{
  "command": "analysis.start",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

呼び出しは `status: "running"` のジョブレコードを返します。

### 3. ジョブの進捗をポーリングする

500 ミリ秒間隔でジョブの状態をポーリングします：

```json
{
  "command": "job.get",
  "jobId": "job-12345"
}
```

または、ジョブの完了まで待機します：

```json
{
  "command": "job.wait",
  "jobId": "job-12345",
  "timeoutMs": 60000
}
```

解析が完了すると、ジョブレコードは `status: "completed"` を示します。

### 4. シンボル検査と逆コンパイル

バイナリ内の関数を一覧表示します：

```json
{
  "command": "function.list",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

シンボルを検査します：

```json
{
  "command": "symbol.list",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

エントリポイントの関数を逆コンパイルします：

```json
{
  "command": "decompilation.get",
  "md5": "0123456789abcdef0123456789abcdef",
  "address": "0x140001000"
}
```

ブリッジは構造化された C 疑似コード、シグネチャ、ローカル変数を返します。

### 5. 変更の保存と終了

プログラムの変更を Ghidra プロジェクトに保存します：

```json
{
  "command": "program.save",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

アクティブなセッションを閉じます：

```json
{
  "command": "session.close",
  "md5": "0123456789abcdef0123456789abcdef"
}
```

## 次のステップ

- よくある問題の解決策については[トラブルシューティング](troubleshooting.md)を参照してください。
- システムの詳細な内部設計については[アーキテクチャ](architecture.md)を参照してください。
