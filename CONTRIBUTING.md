# Contribute to ghidra-mcp

Thank you for your contribution.
This guide tells you how to build, check and change `ghidra-mcp`.

## Repository layout

The Rust code is the root package in a Cargo workspace.
Its modules are in `src/`. `src/main.rs` lists them.
The command `cargo xtask build` builds the bridge and the workspace.
The `xtask/` directory contains automation tools.

The Java bridge is the Git submodule `bridge/`.
After you clone the repository, get the submodule:

```sh
git clone --recurse-submodules <repo>
# For a clone that you made before:
git submodule update --init --recursive
```

Read [docs/architecture.md](docs/architecture.md) before you make a large change.
It describes the processes, the request flows, the session lifecycle, the concurrency rules and the security model.

## Prerequisites

- **Rust** (stable, edition 2021). Get it from <https://rustup.rs>.
- **Java 21.** The bridge build runs the Gradle wrapper. The wrapper needs Java.
  The first build also downloads Gradle.
- **Ghidra 12.1**, in `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME`. The bridge compiles against Ghidra.

## Build and check

```sh
# Build the bridge and the workspace.
cargo xtask build --workspace --locked

# Do the checks that CI does. Do them before you open a pull request.
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked

# Read the API documentation of each module and item.
cargo doc --no-deps --document-private-items --open
```

CI does the format, lint, documentation and build checks on macOS, Linux and Windows.

The supported release is the executable from a recursive source checkout or GitHub Releases.
The Cargo package is not published to crates.io because its build needs the bridge submodule.

### Manual checks

Do these by hand if your change applies to them:

1. Make the runtime bridge files read-only.
   Then open a session.
   - With `wait=false`, the call fails, or it returns the MD5 and the launch job. Then the session goes to `error` and the job goes to `failed`.
   - With `wait=true`, the call returns the error.
   - A relaunch also reports the error. After a failed launch, a new launch must be possible.
2. Ctrl-C stops a foreground daemon, and all its Ghidra processes stop.
3. On Windows, the daemon starts detached from the client.

## Code standard

The lints in `Cargo.toml` enforce most of these rules.
CI changes each warning into an error.

### Format and lints

- `rustfmt` formats all code with standard Rust formatting. Run `cargo fmt --all`.
- Clippy runs with the `pedantic` group. Correct each warning. Do not hide it.
- If a warning is not correct for one item, put `#[expect(clippy::lint, reason = "…")]` on that item. Do not add a crate-wide `allow`.

### Structure

- Use methods on `McpState` and plain functions. Do not add service wrapper types.
- Add a module only for a separate responsibility.
- Dependencies go in one direction: front ends, `tools`, `session` and `analysis`, `bridge`, `state`, platform modules. The layer diagram in docs/architecture.md shows them.
- Do not keep a `std::sync::Mutex` guard across an `.await`.
- Get the lifecycle lock before a session lifecycle transition.
- Use `DomainError` for domain failures and protocol error codes. Use `anyhow` to attach context to other errors.
- An error message names the object and the problem.
- A message to a client must not contain an absolute path or a credential.

### Rust documentation

- Document each item, also the private items (`clippy::missing_docs_in_private_items`).
- Start each module with `//!` text. It tells the responsibility of the module.
  Where applicable, it also tells the invariants, the file formats or the protocols.
- The first line of an item is one sentence, for example "Returns …" or "Starts …". For a type, a field or a constant, you can use a noun phrase.
- Add more paragraphs only for information that the signature does not give.
- A fallible function that other modules use has an `# Errors` section. It lists the conditions that cause an error.
- Use intra-doc links, for example `` [`McpState`] ``. CI examines them.
- Document a wire format at its definition. The field documentation tells what the clients see.

### Comments

- A comment gives the reason for the code.
  Reasons include a security check, a race, a platform difference, an order, or a protocol detail.
  Do not repeat the code.
- Each `unsafe` block has a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks`). The comment tells why each precondition of the call is true.
- Use a safe API from std or from a crate when one is available.

## English standard

All English text obeys ASD-STE100 Simplified Technical English (STE).
This rule applies to the documents, the Rust documentation, the comments, the command-line help and the issue templates.
STE makes the text clear for readers who do not speak English as their first language. It also makes translation easier.

We use these STE rules:

- **Short sentences.** An instruction has a maximum of 20 words. A description has a maximum of 25 words. A paragraph has a maximum of six sentences.
- **One topic in each sentence.** Write one instruction in each sentence.
- **Active voice.** Write "The daemon starts the bridge", not "The bridge is started". You can use passive voice only in descriptions, when the agent is unknown or not important.
- **Simple verb forms.** Use the present, the simple past and the simple future. Write instructions as commands.
- **Clear modal verbs.** Use "must" for a requirement and "can" for a possibility. Do not use "should", "may", "might", "could" or "would".
- **No -ing forms**, except in technical names, for example "coding agent".
- **No phrasal verbs.** Write "start", not "start up". Write "remove", not "get rid of".
- **One definition for each word.** Use terms consistently. Do not use a synonym for a defined term.
- **Simple words.** Write "make sure", "let", "get", "use" and "through". Do not write "ensure", "allow", "obtain", "utilize" and "via".
- **No Latin abbreviations.** Write "for example" and "that is". Do not write "e.g.", "i.e." and "etc.".
- **Articles.** Use "the" and "a" where English grammar needs them.
- **Short noun clusters.** Do not put more than three nouns together.
- **Lists for steps.** Write a procedure as a numbered list. Write one action in each step.

Code, identifiers, commands, file names and quoted output stay as they are.
Error messages are part of the client contract. Change them only in a deliberate change.

Run `cargo xtask simplified-english` to check prohibited words and text length.
Also review word definitions, articles, noun clusters and voice by hand.

### Translations

`README.md` and `docs/architecture.md` have translations:

- Chinese: `README.zh-CN.md` and `docs/zh/`.
- Japanese: `README.ja-JP.md` and `docs/ja/`.

The English document is the source.
When you change an English document, change the translations in the same pull request.
If you cannot translate, state this in the pull request. A maintainer then updates the translations.

Each translation has the same structure, the same examples and the same links as its source.
The title of a translated document keeps the English title in parentheses, for example `体系架构 (Architecture)`.
Use the same translation for a term in all documents. Each document also has a language switcher line below its title.
Do not translate code, identifiers, commands, file names and command output.

## Extend the code

- A new local command is one entry in `LOCAL_COMMANDS` (`src/tools.rs`), with a `Deserialize` argument struct.
- A new session state transition is a `mark_*` method on `SessionRecord` (`src/model.rs`).
- docs/architecture.md gives the procedures for other changes.

## Commands that change the program

Some commands change the analyzed program, for example a patch of a function, a new symbol name, a data type change or a memory patch.
The bridge contract `bridge/docs/asyncapi.yaml` gives the bridge commands and their `mutation` flags.
`src/bridge.rs` reads the contract at compile time.
The daemon sends only the methods in the contract.
When you add or change such a command, make sure that the `read_only` effect in the contract is correct.

## Commit messages

Use the [commit message rules](AGENTS.md#commit-messages).

## Report a problem

Open a GitHub issue with the bug report form or the feature request form.
For a bug, give this information:

- What you tried to do, and what occurred.
- `daemon.log` and `logs/<md5>/stderr.log` from the runtime directory. The README tells where it is. Remove credentials and private paths.
- Your operating system, the output of `ghidra-mcp --version`, and your Ghidra and Java versions.

Report security problems privately. [SECURITY.md](SECURITY.md) tells you how.
Do not report them in a public issue.
