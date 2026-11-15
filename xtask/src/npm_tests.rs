// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests the npm package generation.

use super::{
    cargo_version, main_manifest, pack, platform_manifest, read_json, template_version, MAIN_DIR,
    PLATFORMS,
};
use crate::workspace;
use serde_json::{json, Value};
use std::fs;

fn template() -> Value {
    read_json(
        &workspace::root()
            .unwrap()
            .join(MAIN_DIR)
            .join("package.json"),
    )
    .unwrap()
}

#[test]
fn platform_manifests_restrict_os_cpu_and_libc() {
    let template = template();
    for platform in &PLATFORMS {
        let manifest = platform_manifest(platform, &template, "9.8.7");
        assert_eq!(manifest["name"], platform.package());
        assert_eq!(manifest["version"], "9.8.7");
        assert_eq!(manifest["os"], json!([platform.os]));
        assert_eq!(manifest["cpu"], json!([platform.cpu]));
        assert_eq!(manifest["license"], template["license"]);
        let expected_libc = if platform.os == "linux" {
            json!(["glibc"])
        } else {
            Value::Null
        };
        assert_eq!(manifest["libc"], expected_libc, "{}", platform.suffix);
    }
}

#[test]
fn main_manifest_pins_each_platform_package() {
    let manifest = main_manifest(template(), "9.8.7").unwrap();
    assert_eq!(manifest["version"], "9.8.7");
    let dependencies = manifest["optionalDependencies"].as_object().unwrap();
    assert_eq!(dependencies.len(), PLATFORMS.len());
    for platform in &PLATFORMS {
        assert_eq!(dependencies[&platform.package()], "9.8.7");
    }
}

#[test]
fn committed_template_agrees_with_platform_table() {
    let template = template();
    let version = template_version(&template).unwrap();
    let dependencies = template["optionalDependencies"].as_object().unwrap();
    assert_eq!(dependencies.len(), PLATFORMS.len());
    for platform in &PLATFORMS {
        assert_eq!(dependencies[&platform.package()], version.as_str());
    }
}

#[test]
fn launcher_and_ci_name_each_platform() {
    let root = workspace::root().unwrap();
    let launcher = workspace::read(&root.join(MAIN_DIR).join("bin/ghidra-mcp.js")).unwrap();
    let workflow = workspace::read(&root.join(".github/workflows/ci.yml")).unwrap();
    for platform in &PLATFORMS {
        let entry = format!("'{}': '{}'", platform.suffix, platform.package());
        assert!(launcher.contains(&entry), "launcher has no entry {entry}");
        let artifact = format!("artifact: {}", platform.artifact);
        assert!(workflow.contains(&artifact), "ci.yml has no {artifact}");
    }
}

#[test]
fn reads_only_the_package_version_from_cargo_toml() {
    let manifest = "[workspace]\nversion = \"0.0.1\"\n[package]\nname = \"a\"\n\
                    version = \"1.2.3\"\n[dependencies]\nversion = \"4\"\n";
    assert_eq!(cargo_version(manifest).unwrap(), "1.2.3");
    assert!(cargo_version("[workspace]\n").is_err());
}

#[test]
fn packs_all_packages_into_an_empty_directory() {
    let base = std::env::temp_dir().join(format!("xtask-npm-{}", std::process::id()));
    let dist = base.join("dist");
    let out = base.join("out");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&dist).unwrap();
    for platform in &PLATFORMS {
        fs::write(dist.join(platform.artifact), platform.suffix).unwrap();
    }

    pack(&dist, &out).unwrap();

    for platform in &PLATFORMS {
        let directory = out.join(platform.suffix);
        let executable = directory.join("bin").join(platform.executable());
        assert_eq!(fs::read_to_string(executable).unwrap(), platform.suffix);
        assert!(directory.join("LICENSE").is_file());
        assert!(directory.join("package.json").is_file());
    }
    assert!(out.join("cli/bin/ghidra-mcp.js").is_file());
    assert!(out.join("cli/README.md").is_file());
    assert!(
        pack(&dist, &out).is_err(),
        "a second pack must not write into a full directory"
    );

    fs::remove_dir_all(&base).unwrap();
}
