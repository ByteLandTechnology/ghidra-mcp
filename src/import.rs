// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Validation and persistence types for binary import flags and `.gpr` attachment.

use crate::error::DomainError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::Path;

/// Firmware extensions that binary persistence keeps on the import file name.
const FIRMWARE_EXTENSIONS: [&str; 4] = ["bin", "hex", "ihex", "srec"];

/// Optional Ghidra loader and language flags for binary imports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOptions {
    /// Ghidra language ID passed to `-processor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processor: Option<String>,
    /// Ghidra compiler specification ID passed to `-cspec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_spec: Option<String>,
    /// Ghidra loader class name passed to `-loader`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader: Option<String>,
    /// Normalized base address passed to `-loader-baseAddr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_address: Option<String>,
}

impl ImportOptions {
    /// Returns `true` when no import flag is set.
    pub fn is_empty(&self) -> bool {
        self.processor.is_none()
            && self.compiler_spec.is_none()
            && self.loader.is_none()
            && self.base_address.is_none()
    }

    /// Validates raw flag strings and returns normalized [`ImportOptions`].
    ///
    /// # Errors
    ///
    /// Fails when a flag is empty, malformed, or contains unsafe characters.
    pub fn from_raw(
        processor: Option<&str>,
        compiler_spec: Option<&str>,
        loader: Option<&str>,
        base_address: Option<&str>,
    ) -> Result<Self> {
        let processor = processor.map(normalize_processor).transpose()?;
        let compiler_spec = compiler_spec.map(normalize_compiler_spec).transpose()?;
        let loader = loader.map(normalize_loader).transpose()?;
        let base_address = base_address.map(normalize_base_address).transpose()?;
        Ok(Self {
            processor,
            compiler_spec,
            loader,
            base_address,
        })
    }

    /// Applies non-empty fields from `overrides` onto `self`.
    pub fn merge_from(&mut self, overrides: &Self) {
        if let Some(processor) = &overrides.processor {
            let processor_changed = self.processor.as_ref() != Some(processor);
            self.processor = Some(processor.clone());
            if processor_changed && overrides.compiler_spec.is_none() {
                self.compiler_spec = None;
            }
        }
        if let Some(compiler_spec) = &overrides.compiler_spec {
            self.compiler_spec = Some(compiler_spec.clone());
        }
        if let Some(loader) = &overrides.loader {
            self.loader = Some(loader.clone());
        }
        if let Some(base_address) = &overrides.base_address {
            self.base_address = Some(base_address.clone());
        }
    }

    /// Fails when `compiler_spec` is set without `processor`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` when `compiler_spec` has no `processor`.
    pub fn validate_complete(&self) -> Result<()> {
        if self.compiler_spec.is_some() && self.processor.is_none() {
            return Err(DomainError::invalid_argument(
                "compilerSpec",
                "compilerSpec requires processor",
            )
            .into());
        }
        Ok(())
    }

    /// Returns the loader name for `analyzeHeadless`, with a `.srec` default.
    pub fn effective_loader<'a>(&'a self, import_path: &Path) -> Option<&'a str> {
        if let Some(loader) = self.loader.as_deref() {
            return Some(loader);
        }
        let is_srec = import_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("srec"));
        is_srec.then_some("MotorolaHexLoader")
    }
}

/// Validated session-open options for binary imports and `.gpr` attachment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Binary import flags.
    pub import: ImportOptions,
    /// Re-import the saved binary and replace its internal Ghidra project.
    pub reimport: bool,
    /// Target program name or project path inside an attached `.gpr` project.
    pub program_name: Option<String>,
}

impl OpenOptions {
    /// Returns `true` when no import flag, reimport flag, or program name is set.
    pub fn is_empty(&self) -> bool {
        self.import.is_empty() && !self.reimport && self.program_name.is_none()
    }

    /// Validates raw session-open options.
    ///
    /// # Errors
    ///
    /// Fails when any option value is malformed.
    pub fn from_raw(
        processor: Option<&str>,
        compiler_spec: Option<&str>,
        loader: Option<&str>,
        base_address: Option<&str>,
        reimport: bool,
        program_name: Option<&str>,
    ) -> Result<Self> {
        let import = ImportOptions::from_raw(processor, compiler_spec, loader, base_address)?;
        let program_name = program_name.map(normalize_program_name).transpose()?;
        Ok(Self {
            import,
            reimport,
            program_name,
        })
    }

    /// Validates compatibility with a local target path (`true` for `.gpr`).
    ///
    /// # Errors
    ///
    /// Fails when `.gpr` options and binary import flags are mixed.
    pub fn validate_for_target(&self, is_gpr: bool) -> Result<()> {
        if is_gpr {
            self.reject_binary_flags_on_gpr()
        } else {
            if self.program_name.is_some() {
                return Err(DomainError::invalid_argument(
                    "programName",
                    "programName is valid only for .gpr project paths",
                )
                .into());
            }
            Ok(())
        }
    }

    /// Rejects binary import flags on `.gpr` projects.
    ///
    /// # Errors
    ///
    /// Fails when `processor`, `compilerSpec`, `loader`, `baseAddress`, or `reimport` is set.
    pub fn reject_binary_flags_on_gpr(&self) -> Result<()> {
        for (present, field) in [
            (self.import.processor.is_some(), "processor"),
            (self.import.compiler_spec.is_some(), "compilerSpec"),
            (self.import.loader.is_some(), "loader"),
            (self.import.base_address.is_some(), "baseAddress"),
            (self.reimport, "reimport"),
        ] {
            if present {
                return Err(DomainError::invalid_argument(
                    field,
                    format!("{field} is not valid when attaching a .gpr project"),
                )
                .into());
            }
        }
        Ok(())
    }
}

/// Returns `true` when `path` has a `.gpr` extension.
pub fn is_gpr_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gpr"))
}

/// Extracts a lowercase firmware extension (`bin`, `hex`, `ihex`, or `srec`).
pub fn sanitized_firmware_extension(file_name: &str) -> Option<&'static str> {
    let path = Path::new(file_name);
    let stem = path.file_stem()?.to_str()?;
    if stem.is_empty() {
        return None;
    }
    let ext = path.extension()?.to_str()?;
    FIRMWARE_EXTENSIONS
        .into_iter()
        .find(|candidate| ext.eq_ignore_ascii_case(candidate))
}

/// Returns the persisted binary file name (`binary` or `binary.<ext>`).
pub fn saved_binary_name(file_name: &str) -> String {
    match sanitized_firmware_extension(file_name) {
        Some(ext) => format!("binary.{ext}"),
        None => "binary".to_string(),
    }
}

/// Encodes UTF-8 text as lowercase hexadecimal for safe script arguments.
pub fn hex_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Validates and trims a Ghidra language ID (`arch:endian:size:variant...`).
///
/// # Errors
///
/// Fails when `value` is empty, starts with `-`, or lacks 4 colon-separated segments.
pub fn normalize_processor(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || trimmed
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || matches!(ch, '/' | '\\'))
    {
        return Err(DomainError::invalid_argument(
            "processor",
            "processor must be a valid Ghidra language ID such as ARM:LE:32:Cortex",
        )
        .into());
    }
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() < 4 || parts.iter().any(|part| part.is_empty()) {
        return Err(DomainError::invalid_argument(
            "processor",
            "processor must have at least 4 colon-separated segments (arch:endian:size:variant)",
        )
        .into());
    }
    if !matches!(parts[1], "LE" | "BE" | "LEBE")
        || !parts[2].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DomainError::invalid_argument(
            "processor",
            "processor must specify LE, BE, or LEBE endianness and a numeric bit size",
        )
        .into());
    }
    Ok(trimmed.to_string())
}

/// Validates and trims a Ghidra compiler specification ID.
///
/// # Errors
///
/// Fails when `value` is empty, starts with `-`, or contains invalid characters.
pub fn normalize_compiler_spec(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let valid_chars = trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'));
    if trimmed.is_empty() || trimmed.starts_with('-') || !valid_chars {
        return Err(DomainError::invalid_argument(
            "compilerSpec",
            "compilerSpec must be a nonempty compiler specification identifier",
        )
        .into());
    }
    Ok(trimmed.to_string())
}

/// Validates and normalizes a Ghidra loader class name to its simple class name.
///
/// # Errors
///
/// Fails when `value` is empty or is not a valid ASCII Java class identifier.
pub fn normalize_loader(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let valid_segments = !trimmed.is_empty()
        && trimmed.split('.').all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        });
    let simple = trimmed.rsplit('.').next().unwrap_or("");
    let valid_class = simple
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic());
    if !valid_segments || !valid_class {
        return Err(DomainError::invalid_argument(
            "loader",
            "loader must be a Ghidra loader class name such as BinaryLoader or IntelHexLoader",
        )
        .into());
    }
    Ok(simple.to_string())
}

/// Validates and normalizes a hexadecimal base address (`0x<hex>` or `<space>:0x<hex>`).
///
/// # Errors
///
/// Fails when `value` is empty or is not a valid hexadecimal address.
pub fn normalize_base_address(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return Err(DomainError::invalid_argument(
            "baseAddress",
            "baseAddress must be a hexadecimal address such as 0x08000000",
        )
        .into());
    }
    if let Some((space, offset)) = trimmed.split_once(':') {
        let mut space_bytes = space.bytes();
        let valid_space = space_bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && space_bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        let hex = parse_hex_offset(offset)?;
        if !valid_space {
            return Err(DomainError::invalid_argument(
                "baseAddress",
                "baseAddress address space prefix is invalid",
            )
            .into());
        }
        return Ok(format!("{space}:0x{hex}"));
    }
    let hex = parse_hex_offset(trimmed)?;
    Ok(format!("0x{hex}"))
}

/// Extracts and validates 1 to 16 hexadecimal digits.
fn parse_hex_offset(raw: &str) -> Result<String> {
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DomainError::invalid_argument(
            "baseAddress",
            "baseAddress must contain 1 to 16 hexadecimal digits",
        )
        .into());
    }
    Ok(digits.to_ascii_lowercase())
}

/// Validates a target program name or project path inside a `.gpr` project.
///
/// # Errors
///
/// Fails for empty strings, control characters, backslashes, or `.` / `..` segments.
pub fn normalize_program_name(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains('\\') || trimmed.chars().any(char::is_control) {
        return Err(DomainError::invalid_argument(
            "programName",
            "programName must be a nonempty name or project path without control characters",
        )
        .into());
    }
    let relative = trimmed.strip_prefix('/').unwrap_or(trimmed);
    if relative.is_empty()
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(DomainError::invalid_argument(
            "programName",
            "programName must not contain empty, '.', or '..' path segments",
        )
        .into());
    }
    Ok(trimmed.to_string())
}
