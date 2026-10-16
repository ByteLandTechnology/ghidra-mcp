# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and files

- A `.rs` file must have no more than 800 lines of code. Comments and blank lines
  are not counted.
- A line must not exceed 100 characters.
- Each `.rs` file must start with the standard license header:
  ```rust
  // Copyright 2026 ByteLand Technology Limited
  // SPDX-License-Identifier: MIT
  ```

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
- Use these scopes:
  - A module name, such as `mcp` or `session`: its code in `src/`.
  - `xtask`: the code in `xtask/`.
  - `docs`: the documents.
  - `build`: build files, such as `Cargo.toml` and `Cargo.lock`.
  - `ci`: workflows and automation in `.github/`.
  - `bridge`: the bridge integration, submodule reference, and `java/` scripts.
  - If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- The body is optional for a small change that needs no explanation.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
  - If an item is too long, write a shorter sentence or divide it.
- The body rules do not apply to footers.
- Do not add attribution to commit messages or pull request text.
- Each commit must compile.

## Verification

Run repository checks with `cargo xtask`:

- `cargo xtask check`: Verifies license headers, code lines, and line widths.
- `cargo xtask ci`: Runs formatting checks, repository checks, clippy, and docs.
- `cargo xtask license-headers [--fix]`: Checks or applies license headers.
- `cargo xtask line-limit`: Verifies code lines per file.
- `cargo xtask line-width`: Verifies character width per line.
- `cargo xtask simplified-english`: Checks documents and comments for automated English rules.
