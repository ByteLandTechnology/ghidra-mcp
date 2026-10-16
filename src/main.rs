// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! `ghidra-mcp`: headless Ghidra analysis for MCP clients.
//!
//! One executable has three roles. The command line selects the role (see [`cli`]):
//!
//! - **Daemon** (`--daemon`): owns all Ghidra sessions. It launches
//!   `analyzeHeadless` with the embedded bridge. The bridge connects to the
//!   daemon through a WebSocket. The daemon serves MCP through HTTP and through
//!   a local socket.
//! - **Stdio proxy** (no arguments): the process that an MCP client starts. It
//!   sends each tool call to the daemon. If necessary, it starts the daemon.
//! - **CLI** (`tools`, `call`): writes the tool definitions, or makes one call
//!   through the daemon.
//!
//! # Modules
//!
//! Dependencies go in one direction, from the front ends to the shared state:
//!
//! | Layer | Modules |
//! |---|---|
//! | Front ends | [`cli`], [`daemon`], [`mcp`], [`mcp_http`], [`upload`] |
//! | Tools | [`tools`] (`ghidra_help` and the domain tools) |
//! | Domain | [`session`], [`analysis`], [`project`] |
//! | Bridge | [`bridge`], [`jsonrpc`] |
//! | State | [`state`], [`model`] |
//! | Platform | [`config`], [`paths`], [`java_path`], [`process`], [`ghidra`] |
//!
//! `docs/architecture.md` in the repository describes the design.

mod analysis;
mod bridge;
mod cli;
mod config;
mod daemon;
mod error;
mod ghidra;
mod java_path;
mod jsonrpc;
mod mcp;
mod mcp_http;
mod model;
mod paths;
mod process;
mod project;
mod session;
mod state;
mod tools;
mod upload;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run().await
}
