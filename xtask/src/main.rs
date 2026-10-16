// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Repository automation and verification tasks for ghidra-mcp.
//!
//! Run `cargo xtask help` for the list of available commands.

mod bridge;
mod build;
mod ci;
mod headers;
mod lexer;
mod licenses;
mod lines;
mod ste;
mod workspace;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Command-line arguments for xtask.
#[derive(Parser)]
#[command(name = "cargo xtask", bin_name = "cargo xtask")]
#[command(about = "Repository automation and verification tasks for ghidra-mcp.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available repository tasks.
#[derive(Subcommand)]
enum Commands {
    /// Build the bridge if it is absent. Then build the workspace.
    Build {
        /// Arguments to pass to cargo build.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Build the Java bridge submodule with Gradle.
    BuildBridge,
    /// Run all checks that CI runs: format, repo checks, clippy, doc.
    Ci,
    /// Run repository checks: license headers, line limit, line width.
    Check,
    /// Check or fix the license header of each Rust file.
    LicenseHeaders {
        /// Fix absent license headers in place.
        #[arg(long)]
        fix: bool,
    },
    /// Check lines of code limit of each Rust file.
    LineLimit,
    /// Check line width limit (100 characters) of each Rust file.
    LineWidth,
    /// Check English prose against the automated STE rules.
    SimplifiedEnglish,
    /// Collect license texts of locked dependencies and bridge.
    CollectLicenses,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::BuildBridge => bridge::build(true),
        Commands::Build { args } => {
            let forwarded: Vec<&str> = args.iter().map(String::as_str).collect();
            build::run(&forwarded)
        }
        Commands::Ci => ci::run(),
        Commands::Check => run_all(),
        Commands::LicenseHeaders { fix } => headers::check(fix),
        Commands::LineLimit => lines::check_code_lines(),
        Commands::LineWidth => lines::check_line_widths(),
        Commands::SimplifiedEnglish => ste::check(),
        Commands::CollectLicenses => licenses::collect(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Runs each repository check and reports all failures.
pub(crate) fn run_all() -> Result<(), String> {
    let failures: Vec<String> = [
        headers::check(false),
        lines::check_code_lines(),
        lines::check_line_widths(),
        ste::check(),
    ]
    .into_iter()
    .filter_map(Result::err)
    .collect();

    if failures.is_empty() {
        println!("Repository checks: OK");
        Ok(())
    } else {
        Err(failures.join("\n\n"))
    }
}
