// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests the English checks for the bridge contract.

use super::check_yaml_contract;
use std::path::Path;

#[test]
fn checks_quoted_and_multiline_descriptions() {
    let source = "\"description\": \"This could\n  fail.\"\n";
    let mut violations = Vec::new();
    check_yaml_contract(Path::new("asyncapi.yaml"), source, &mut violations).unwrap();
    assert!(violations.iter().any(|item| item.message.contains("could")));
}

#[test]
fn rejects_invalid_yaml_contracts() {
    let mut violations = Vec::new();
    assert!(check_yaml_contract(Path::new("asyncapi.yaml"), "[", &mut violations).is_err());
}
