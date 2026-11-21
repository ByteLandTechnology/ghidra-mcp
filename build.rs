// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Checks the bridge MCP tool contract at build time.
//!
//! Each `ghidra-mcp` operation tool merges `md5` with the operation properties
//! at the top level. This script fails the build if a bridge tool schema
//! defines a top-level `md5` property.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Subset of JSON values needed to inspect tool schemas.
enum Json {
    /// A JSON literal or number that schema checks do not inspect.
    Scalar,
    /// A JSON string value.
    Str(String),
    /// A JSON array value.
    Array(Vec<Self>),
    /// A JSON object value as key-value pairs.
    Object(Vec<(String, Self)>),
}

impl Json {
    /// Looks up a field in a JSON object.
    fn get(&self, key: &str) -> Option<&Self> {
        let Self::Object(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find_map(|(entry_key, value)| (entry_key == key).then_some(value))
    }

    /// Returns the string slice if this value is a JSON string.
    fn as_str(&self) -> Option<&str> {
        let Self::Str(value) = self else {
            return None;
        };
        Some(value)
    }
}

/// Byte cursor over UTF-8 JSON input.
struct Parser<'a> {
    /// Raw UTF-8 bytes of the JSON document.
    bytes: &'a [u8],
    /// Current byte offset in `bytes`.
    pos: usize,
}

impl<'a> Parser<'a> {
    /// Creates a parser at the start of `source`.
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            pos: 0,
        }
    }

    /// Advances past ASCII whitespace.
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// Reads the next non-whitespace byte and leaves the cursor at that byte.
    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    /// Skips whitespace and advances past `expected`.
    fn expect(&mut self, expected: u8) {
        let actual = self.peek();
        assert!(
            actual == Some(expected),
            "expected `{}` at byte {}, got {actual:?}",
            char::from(expected),
            self.pos
        );
        self.pos += 1;
    }

    /// Parses one JSON value.
    fn parse_value(&mut self) -> Json {
        match self.peek().expect("unexpected end of JSON input") {
            b'"' => Json::Str(self.parse_string()),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b't' => self.parse_literal(b"true"),
            b'f' => self.parse_literal(b"false"),
            b'n' => self.parse_literal(b"null"),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => panic!(
                "unexpected JSON byte `{}` at {}",
                char::from(other),
                self.pos
            ),
        }
    }

    /// Consumes an exact JSON keyword literal.
    fn parse_literal(&mut self, literal: &[u8]) -> Json {
        self.skip_ws();
        let end = self.pos + literal.len();
        assert!(
            self.bytes.get(self.pos..end) == Some(literal),
            "invalid JSON literal at byte {}",
            self.pos
        );
        self.pos = end;
        Json::Scalar
    }

    /// Consumes a JSON number token.
    fn parse_number(&mut self) -> Json {
        self.skip_ws();
        while let Some(byte) = self.bytes.get(self.pos) {
            if matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        Json::Scalar
    }

    /// Parses a JSON string value.
    fn parse_string(&mut self) -> String {
        self.expect(b'"');
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            self.pos += 1;
            match byte {
                b'"' => return out,
                b'\\' => {
                    let escaped = *self.bytes.get(self.pos).expect("unterminated escape");
                    self.pos += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => out.push(char::from(escaped)),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(
                                self.bytes
                                    .get(self.pos..self.pos + 4)
                                    .expect("short unicode escape"),
                            )
                            .expect("unicode escape must be ASCII");
                            self.pos += 4;
                            let code = u32::from_str_radix(hex, 16).expect("invalid hex escape");
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        other => panic!("unsupported escape `\\{}`", char::from(other)),
                    }
                }
                _ => {
                    self.pos -= 1;
                    let rest = std::str::from_utf8(&self.bytes[self.pos..]).expect("valid UTF-8");
                    let ch = rest.chars().next().expect("character");
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
        panic!("unterminated JSON string");
    }

    /// Parses a JSON array value.
    fn parse_array(&mut self) -> Json {
        self.expect(b'[');
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Json::Array(items);
        }
        loop {
            items.push(self.parse_value());
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Json::Array(items);
                }
                other => panic!("expected `,` or `]` at {}, got {other:?}", self.pos),
            }
        }
    }

    /// Parses a JSON object value.
    fn parse_object(&mut self) -> Json {
        self.expect(b'{');
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Json::Object(entries);
        }
        loop {
            let key = self.parse_string();
            self.expect(b':');
            let value = self.parse_value();
            entries.push((key, value));
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Json::Object(entries);
                }
                other => panic!("expected `,` or `}}` at {}, got {other:?}", self.pos),
            }
        }
    }
}

/// Validates that no bridge tool defines a reserved `md5` input property.
fn main() {
    println!("cargo::rerun-if-changed=bridge/docs/mcp-tools.json");
    println!("cargo::rerun-if-changed=bridge/docs/asyncapi.yaml");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let contract_path = manifest_dir.join("bridge/docs/mcp-tools.json");
    let source = fs::read_to_string(&contract_path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}", contract_path.display());
    });

    let mut parser = Parser::new(&source);
    let root = parser.parse_value();
    parser.skip_ws();
    assert_eq!(
        parser.pos,
        parser.bytes.len(),
        "trailing bytes in {}",
        contract_path.display()
    );

    let Some(Json::Array(tools)) = root.get("tools") else {
        panic!("`tools` array is absent in {}", contract_path.display());
    };
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Json::as_str)
            .expect("bridge tool name");
        let schema = tool.get("inputSchema").expect("bridge tool inputSchema");
        assert_eq!(
            schema.get("type").and_then(Json::as_str),
            Some("object"),
            "bridge tool `{name}` inputSchema must have type=object"
        );
        for combinator in ["oneOf", "anyOf"] {
            assert!(
                schema.get(combinator).is_none(),
                "bridge tool `{name}` inputSchema has top-level `{combinator}`"
            );
        }
        let Some(Json::Object(properties)) = schema.get("properties") else {
            panic!("bridge tool `{name}` inputSchema has no `properties` object");
        };
        assert!(
            properties.iter().all(|(key, _)| key != "md5"),
            "bridge tool `{name}` defines reserved top-level property `md5`"
        );
    }
}
