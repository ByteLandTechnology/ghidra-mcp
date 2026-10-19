# トラブルシューティング (Troubleshooting)

[English](../troubleshooting.md) | [中文](../zh/troubleshooting.md) | [日本語](troubleshooting.md)

この運用手順書は `ghidra-mcp` の一般的な問題を診断し解決するのに役立ちます。

## 目次

- [1. ヘッドレス実行ファイルの検出](#1-ヘッドレス実行ファイルの検出)
- [2. Java 21 環境設定](#2-java-21-環境設定)
- [3. ソケットおよびパイプの権限](#3-ソケットおよびパイプの権限)
- [4. メモリ制限と大規模バイナリの設定](#4-メモリ制限と大規模バイナリの設定)
- [5. ログ診断とエラーコード](#5-ログ診断とエラーコード)

## 1. ヘッドレス実行ファイルの検出

### 症状

- デーモンが起動時に終了コード `1` で終了する。
- stderr と `daemon.log` に、`analyzeHeadless` が見つからないか、実行できないと表示される。

### 検出の優先順位

デーモンは次の順序で `analyzeHeadless` を検索します：

1. `config.toml` 内の `[ghidra].analyze_headless`。
2. `config.toml` 内の `[ghidra].home`、または `GHIDRA_INSTALL_DIR` / `GHIDRA_HOME` 環境変数。
3. システム `PATH` 上の `analyzeHeadless`。
4. システム `PATH` 上の `ghidraRun`。
5. 標準ディレクトリ：`/Applications/ghidra*`、`/opt/homebrew/Caskroom/ghidra/*`、`~/Applications`、`~`、`~/opt`。

### 解決策

環境または MCP クライアント設定で `GHIDRA_INSTALL_DIR` を設定します：

```sh
export GHIDRA_INSTALL_DIR="/path/to/ghidra_12.1.4_PUBLIC"
```

Windows の場合：

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.1.4_PUBLIC"
```

または、永続ホームディレクトリの `config.toml` で設定します：

```toml
[ghidra]
home = "/path/to/ghidra_12.1.4_PUBLIC"
```

## 2. Java 21 環境設定

### 症状

- セッション開始時に Ghidra が直ちにクラッシュする。
- ログに `UnsupportedClassVersionError: ... class file version 65.0` と表示される。

### 原因

Ghidra 11 以降および組み込みブリッジランタイムには Java 21 JDK が必要です。
古い Java バージョンではクラスファイルを実行できません。

### 解決策

1. Java バージョンを確認します：

   ```sh
   java -version
   ```

2. OpenJDK 21 または Eclipse Temurin 21 をインストールします。
3. `JAVA_HOME` を Java 21 のインストール先を指すように設定します：

   ```sh
   export JAVA_HOME="/usr/lib/jvm/java-21-openjdk"
   ```

4. MCP クライアントまたはデーモンを再起動します。

## 3. ソケットおよびパイプの権限

### 症状

- MCP クライアントが `ConnectionRefused` または `PermissionDenied` で失敗する。
- プロキシがデーモンに接続できない。

### Unix ドメインソケット

デーモンは Unix ソケットを `<runtime_dir>/daemon.sock` に保存します。
ランタイムディレクトリには `0700` のパーミッションモードが必要です。
ソケットファイルには `0600` のパーミッションモードが必要です。
クライアントプロセスとデーモンプロセスは同じユーザー UID で実行する必要があります。

権限を確認します：

```sh
ls -ld /run/user/$UID/ghidra-mcp-*
ls -l /run/user/$UID/ghidra-mcp-*/daemon.sock
```

必要に応じてディレクトリの権限を修正します：

```sh
chmod 0700 /run/user/$UID/ghidra-mcp-*
```

### Windows 名前付きパイプ

デーモンは名前付きパイプ `\\.\pipe\ghidra-mcp-<uuid>` を作成します。
パイプは所有者専用の DACL 記述子 `D:P(A;;GA;;;OW)` を強制します。
MCP クライアントは同じ Windows ユーザーアカウントで実行する必要があります。
パイプへのアクセス権がないサンドボックス環境やコンテナプロセスは接続できません。

## 4. メモリ制限と大規模バイナリの設定

### 症状

- Ghidra 解析が `java.lang.OutOfMemoryError` でクラッシュする。
- 50 MB を超えるバイナリまたは複雑なファームウェアによりメモリ使用量が高くなります。

### JVM ヒープメモリの設定

`JAVA_TOOL_OPTIONS` を通じて JVM ヒープ上限を増やします：

```sh
export JAVA_TOOL_OPTIONS="-Xmx8G -Xms2G"
```

Windows の場合：

```powershell
$env:JAVA_TOOL_OPTIONS = "-Xmx8G -Xms2G"
```

### CPU 並行数の制限

`config.toml` で解析用の CPU コア数を制限します：

```toml
[analysis]
max_cpu = 2
```

スレッド数を減らすと、並列解析時のピークメモリ使用量が減ります。

### ログの上限と切り捨て

デーモンはすべてのログファイル（`daemon.log`、`stdout.log`、`stderr.log`）を 10 MiB に制限します。
ログファイルが 10 MiB に達すると、デーモンはローテーションを行い、最大 3 世代のバックアップ（`.1`、`.2`、`.3`）を保持します。
フォワーダーは 10 MiB を超える 1 行のログを `[TRUNCATED_LOG_LINE]` で切り捨てます。

## 5. ログ診断とエラーコード

### ログの場所

問題を診断するには、以下のログファイルを確認してください：

- デーモンログ：`<runtime_dir>/daemon.log`
- 子プロセス標準出力：`<runtime_dir>/logs/<md5>/stdout.log`
- 子プロセス標準エラー：`<runtime_dir>/logs/<md5>/stderr.log`

デーモンはログ内の機密 bearer トークンを `[REDACTED_TOKEN]` に置き換えます。

### JSON-RPC エラーコード

ツール呼び出しは `structuredContent` 内で標準 JSON-RPC 2.0 エラーコードを返します：

| コード | 名前 | 原因 | 解決策 |
| --- | --- | --- | --- |
| `-32602` | `invalid_argument` | 未知のツール、またはツール引数や操作パラメータが存在しないか無効。 | `ghidra_help` でパラメータを確認します。 |
| `-32001` | `session_lock_timeout` | セッションロックのタイムアウトまたは競合。 | 実行中の操作の終了を待ちます。 |
| `-32002` | `missing_target` | 対象のバイナリ、セッション、ジョブ ID、ドメイン、操作が見つからない。 | 先にセッションを開くかアップロードします。 |
| `-32000` | `disconnected` | ブリッジが切断されたかデーモンの停止処理中。 | `ghidra_session open` で再度開きます。 |
| `-32603` | `transaction_failed` | 内部データベーストランザクションまたはブリッジの障害。 | 子プロセスのログを確認します。 |
