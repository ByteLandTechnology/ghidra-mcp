// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Checks automated STE rules in English documents and source comments.

use std::fs;
use std::path::{Path, PathBuf};

use crate::workspace;

/// Maximum number of words in an instruction.
const INSTRUCTION_WORD_LIMIT: usize = 20;

/// Maximum number of words in a description.
const DESCRIPTION_WORD_LIMIT: usize = 25;

/// Maximum number of sentences in one paragraph.
const PARAGRAPH_SENTENCE_LIMIT: usize = 6;

/// Words that the repository rules prohibit in prose.
const FORBIDDEN_WORDS: &[&str] = &[
    "allow",
    "allows",
    "allowed",
    "allowing",
    "could",
    "ensure",
    "ensures",
    "ensured",
    "ensuring",
    "may",
    "might",
    "obtain",
    "obtains",
    "obtained",
    "obtaining",
    "should",
    "utilize",
    "utilizes",
    "utilized",
    "utilizing",
    "via",
    "would",
];

/// Contractions that the repository rules prohibit in prose.
const CONTRACTIONS: &[&str] = &[
    "aren't",
    "can't",
    "couldn't",
    "didn't",
    "doesn't",
    "don't",
    "hadn't",
    "hasn't",
    "haven't",
    "isn't",
    "mustn't",
    "shouldn't",
    "wasn't",
    "weren't",
    "won't",
    "wouldn't",
];

/// Phrasal verbs that the repository rules prohibit in prose.
const PHRASAL_VERBS: &[&str] = &[
    "carry out",
    "check out",
    "clean up",
    "come back",
    "find out",
    "get rid of",
    "go away",
    "look at",
    "look for",
    "put together",
    "set up",
    "shut down",
    "start up",
    "try again",
    "turn off",
    "turn on",
];

/// Technical names and words that only end with the letters `ing`.
const ING_EXCEPTIONS: &[&str] = &[
    "coding",
    "contributing",
    "during",
    "encoding",
    "engineering",
    "formatting",
    "ing",
    "launching",
    "nothing",
    "operating",
    "ping",
    "rebinding",
    "starting",
    "string",
    "troubleshooting",
    "warning",
];

/// Verbs that identify an instruction when they are the first word.
const INSTRUCTION_VERBS: &[&str] = &[
    "add",
    "build",
    "call",
    "check",
    "choose",
    "clone",
    "close",
    "configure",
    "connect",
    "copy",
    "create",
    "define",
    "delete",
    "describe",
    "download",
    "edit",
    "enter",
    "examine",
    "give",
    "include",
    "install",
    "keep",
    "limit",
    "list",
    "make",
    "merge",
    "open",
    "pass",
    "put",
    "read",
    "register",
    "remove",
    "replace",
    "report",
    "review",
    "run",
    "save",
    "select",
    "send",
    "set",
    "start",
    "stop",
    "submit",
    "use",
    "verify",
    "wait",
    "write",
];

/// One STE rule violation.
struct Violation {
    /// File that has the violation.
    path: PathBuf,
    /// First line of the text that has the violation.
    line: usize,
    /// Description of the violation.
    message: String,
}

/// Checks all English documents and source comments with the automated rules.
pub(crate) fn check() -> Result<(), String> {
    let mut files = Vec::new();
    collect_files(&workspace::root()?, &mut files)?;
    files.sort();

    let mut violations = Vec::new();
    for path in files {
        let source = workspace::read(&path)?;
        match path.extension().and_then(|value| value.to_str()) {
            Some("md") => check_markdown(&path, &source, &mut violations),
            Some("rs" | "java" | "template" | "gradle") => {
                check_slash_comments(&path, &source, &mut violations);
            }
            Some("sh") => check_hash_comments(&path, &source, &mut violations),
            Some("toml") => check_toml(&path, &source, &mut violations),
            Some("json") => check_json(&path, &source, &mut violations),
            Some("yml" | "yaml") if source.trim_start().starts_with('{') => {
                check_json(&path, &source, &mut violations);
            }
            Some("yml" | "yaml") => check_yaml(&path, &source, &mut violations),
            Some("svg") => check_svg(&path, &source, &mut violations),
            _ => {}
        }
    }

    if violations.is_empty() {
        println!("Simplified English: OK");
        return Ok(());
    }

    let details = violations
        .iter()
        .map(|item| {
            format!(
                "  {}:{}: {}",
                workspace::display(&item.path),
                item.line,
                item.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Err(format!(
        "Simplified English: found {} violation(s):\n{details}",
        violations.len()
    ))
}

/// Collects files that can contain English documents or source comments.
fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", workspace::display(directory)))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", workspace::display(directory)))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", workspace::display(&path)))?;
        if kind.is_dir() {
            if !is_ignored_directory(&name) {
                collect_files(&path, files)?;
            }
        } else if kind.is_file() && is_checked_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

/// Returns `true` for a directory that the check must not enter.
fn is_ignored_directory(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".gradle" | ".worktrees" | "build" | "node_modules" | "target" | "ja" | "zh"
    )
}

/// Returns `true` for a file that can contain text in the check scope.
fn is_checked_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if name == "CHANGELOG.md" || name.contains(".ja-") || name.contains(".zh-") {
        return false;
    }
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some(
            "gradle"
                | "java"
                | "json"
                | "md"
                | "rs"
                | "sh"
                | "svg"
                | "template"
                | "toml"
                | "yaml"
                | "yml"
        )
    )
}

/// Checks prose in one Markdown file.
fn check_markdown(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let mut paragraph = String::new();
    let mut paragraph_line = 0;
    let mut in_fence = false;
    for (index, line) in source.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            flush(path, paragraph_line, &mut paragraph, violations);
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || is_table_separator(trimmed) {
            flush(path, paragraph_line, &mut paragraph, violations);
            continue;
        }
        if trimmed.starts_with('|') {
            flush(path, paragraph_line, &mut paragraph, violations);
            for cell in trimmed.trim_matches('|').split('|') {
                check_text(path, number, cell, violations);
            }
            continue;
        }
        if is_separate_markdown_line(trimmed) {
            flush(path, paragraph_line, &mut paragraph, violations);
            check_text(path, number, trim_markdown_prefix(trimmed), violations);
            continue;
        }
        if paragraph.is_empty() {
            paragraph_line = number;
        } else {
            paragraph.push(' ');
        }
        paragraph.push_str(trimmed);
    }
    flush(path, paragraph_line, &mut paragraph, violations);
}

/// Returns `true` for a Markdown table separator.
fn is_table_separator(text: &str) -> bool {
    let value = text.trim_matches('|').trim();
    !value.is_empty()
        && value
            .chars()
            .all(|character| matches!(character, '-' | ':' | '|' | ' '))
}

/// Returns `true` when one Markdown line is a separate prose unit.
fn is_separate_markdown_line(text: &str) -> bool {
    text.starts_with("- ")
        || text.starts_with("* ")
        || text.starts_with("+ ")
        || text.starts_with("> ")
        || text.starts_with("<!--")
        || has_numbered_prefix(text)
}

/// Returns `true` for a Markdown numbered-list prefix.
fn has_numbered_prefix(text: &str) -> bool {
    let digits = text.chars().take_while(char::is_ascii_digit).count();
    digits > 0
        && text
            .get(digits..)
            .is_some_and(|rest| rest.starts_with(". ") || rest.starts_with(") "))
}

/// Removes a Markdown list, quote, or comment prefix.
fn trim_markdown_prefix(mut text: &str) -> &str {
    if text.starts_with("<!--") {
        return text
            .trim_start_matches("<!--")
            .trim_end_matches("-->")
            .trim();
    }
    if matches!(text.as_bytes().first(), Some(b'-' | b'*' | b'+' | b'>')) {
        return text.get(1..).unwrap_or("").trim_start();
    }
    let digits = text.chars().take_while(char::is_ascii_digit).count();
    text = text.get(digits..).unwrap_or(text);
    text.strip_prefix(". ")
        .or_else(|| text.strip_prefix(") "))
        .unwrap_or(text)
}

/// Checks whole-line slash comments and documentation comments.
fn check_slash_comments(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let mut paragraph = String::new();
    let mut paragraph_line = 0;
    let mut in_block = false;
    let mut in_fence = false;
    for (index, line) in source.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        let mut comment = None;
        if in_block {
            let value = trimmed.strip_suffix("*/").unwrap_or(trimmed).trim();
            let value = value.trim_start_matches('*').trim();
            comment = Some(value);
            if trimmed.contains("*/") {
                in_block = false;
            }
        } else if let Some(value) = trimmed.strip_prefix("//") {
            comment = Some(value.trim_start_matches(['/', '!']).trim());
        } else if let Some(value) = trimmed.strip_prefix("/*") {
            in_block = !trimmed.contains("*/");
            comment = Some(value.trim_start_matches('*').trim_end_matches("*/").trim());
        }
        let Some(text) = comment else {
            flush(path, paragraph_line, &mut paragraph, violations);
            continue;
        };
        if text.starts_with("```") {
            flush(path, paragraph_line, &mut paragraph, violations);
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        push_comment_text(
            path,
            number,
            text,
            &mut paragraph_line,
            &mut paragraph,
            violations,
        );
    }
    flush(path, paragraph_line, &mut paragraph, violations);
}

/// Checks whole-line hash comments.
fn check_hash_comments(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let mut paragraph = String::new();
    let mut paragraph_line = 0;
    for (index, line) in source.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("#!") {
            continue;
        }
        if let Some(text) = trimmed.strip_prefix('#') {
            push_comment_text(
                path,
                number,
                text.trim(),
                &mut paragraph_line,
                &mut paragraph,
                violations,
            );
        } else {
            flush(path, paragraph_line, &mut paragraph, violations);
        }
    }
    flush(path, paragraph_line, &mut paragraph, violations);
}

/// Checks comments and package descriptions in a TOML file.
fn check_toml(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    check_hash_comments(path, source, violations);
    for (index, line) in source.lines().enumerate() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "description" {
            check_text(path, index + 1, value.trim().trim_matches('"'), violations);
        }
    }
}

/// Adds one comment line to its paragraph or checks it separately.
fn push_comment_text(
    path: &Path,
    line: usize,
    text: &str,
    paragraph_line: &mut usize,
    paragraph: &mut String,
    violations: &mut Vec<Violation>,
) {
    if text.is_empty() {
        flush(path, *paragraph_line, paragraph, violations);
        return;
    }
    if text.starts_with('|') {
        flush(path, *paragraph_line, paragraph, violations);
        if !is_table_separator(text) {
            for cell in text.trim_matches('|').split('|') {
                check_text(path, line, cell, violations);
            }
        }
        return;
    }
    if text.starts_with('@') || is_separate_markdown_line(text) || text.starts_with('#') {
        flush(path, *paragraph_line, paragraph, violations);
        check_text(path, line, trim_markdown_prefix(text), violations);
        return;
    }
    if paragraph.is_empty() {
        *paragraph_line = line;
    } else {
        paragraph.push(' ');
    }
    paragraph.push_str(text);
}

/// Checks comments and human-readable scalar values in a YAML file.
fn check_yaml(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    check_hash_comments(path, source, violations);
    let mut block_indent = None;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if let Some(required_indent) = block_indent {
            if trimmed.is_empty() {
                continue;
            }
            if indent > required_indent {
                check_text(path, index + 1, trimmed, violations);
                continue;
            }
            block_indent = None;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim_start_matches("- ").trim();
        if matches!(key, "description" | "placeholder" | "value")
            && matches!(value.trim(), "|" | ">" | "|-" | ">-")
        {
            block_indent = Some(indent);
        } else if matches!(key, "about" | "description" | "label" | "name")
            && !value.trim().is_empty()
        {
            check_text(path, index + 1, value.trim(), violations);
        }
    }
}

/// Checks descriptions and titles in a JSON document.
fn check_json(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let Ok(value) = serde_json::from_str(source) else {
        return;
    };
    check_json_value(path, &value, violations);
}

/// Checks documentation strings in one JSON value and its children.
fn check_json_value(path: &Path, value: &serde_json::Value, violations: &mut Vec<Violation>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if matches!(key.as_str(), "description" | "title") {
                    if let Some(text) = child.as_str() {
                        check_vocabulary(path, 1, text, violations);
                    }
                }
                check_json_value(path, child, violations);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                check_json_value(path, child, violations);
            }
        }
        _ => {}
    }
}

/// Checks comments and visible text in an SVG file.
fn check_svg(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    for (index, line) in source.lines().enumerate() {
        let number = index + 1;
        if let Some(start) = line.find("<!--") {
            let text = &line[start + 4..];
            check_text(
                path,
                number,
                text.trim_end_matches("-->").trim(),
                violations,
            );
        }
        if line.contains("<text") {
            check_text(path, number, line, violations);
        }
    }
}

/// Checks a completed paragraph and clears its buffer.
fn flush(path: &Path, line: usize, paragraph: &mut String, violations: &mut Vec<Violation>) {
    if paragraph.is_empty() {
        return;
    }
    check_text(path, line, paragraph, violations);
    paragraph.clear();
}

/// Checks one prose unit for vocabulary and length rules.
fn check_text(path: &Path, line: usize, text: &str, violations: &mut Vec<Violation>) {
    let visible = visible_text(text);
    check_vocabulary(path, line, text, violations);
    check_lengths(path, line, &visible, violations);
}

/// Checks one prose unit for vocabulary rules.
fn check_vocabulary(path: &Path, line: usize, text: &str, violations: &mut Vec<Violation>) {
    let visible = visible_text(text);
    let lower = visible.to_ascii_lowercase();
    let words = words(&lower);
    for forbidden in FORBIDDEN_WORDS {
        if words.iter().any(|word| word == forbidden) {
            add_violation(
                path,
                line,
                format!("prohibited word: {forbidden}"),
                violations,
            );
        }
    }
    for contraction in CONTRACTIONS {
        if words.iter().any(|word| word == contraction) {
            add_violation(
                path,
                line,
                format!("contraction: {contraction}"),
                violations,
            );
        }
    }
    for phrase in PHRASAL_VERBS {
        if contains_phrase(&words, phrase) {
            add_violation(path, line, format!("phrasal verb: {phrase}"), violations);
        }
    }
    for abbreviation in ["e.g.", "i.e.", "etc."] {
        if lower.contains(abbreviation) {
            add_violation(
                path,
                line,
                format!("Latin abbreviation: {abbreviation}"),
                violations,
            );
        }
    }
    for word in &words {
        if word.ends_with("ing") && !ING_EXCEPTIONS.contains(&word.as_str()) {
            add_violation(
                path,
                line,
                format!("nontechnical -ing form: {word}"),
                violations,
            );
        }
    }
}

/// Checks sentence and paragraph lengths in one prose unit.
fn check_lengths(path: &Path, line: usize, text: &str, violations: &mut Vec<Violation>) {
    let sentences = split_sentences(text);
    if sentences.len() > PARAGRAPH_SENTENCE_LIMIT {
        add_violation(
            path,
            line,
            format!(
                "paragraph has {} sentences; maximum is {PARAGRAPH_SENTENCE_LIMIT}",
                sentences.len()
            ),
            violations,
        );
    }
    for sentence in sentences {
        let sentence = sentence
            .find("**:")
            .and_then(|index| sentence.get(index + 3..))
            .unwrap_or(sentence);
        let sentence_words = words(sentence);
        if sentence_words.is_empty() {
            continue;
        }
        let is_instruction = INSTRUCTION_VERBS.contains(&sentence_words[0].as_str());
        let limit = if is_instruction {
            INSTRUCTION_WORD_LIMIT
        } else {
            DESCRIPTION_WORD_LIMIT
        };
        if sentence_words.len() > limit {
            add_violation(
                path,
                line,
                format!(
                    "sentence has {} words; maximum is {limit}",
                    sentence_words.len()
                ),
                violations,
            );
        }
    }
}

/// Removes code, quoted text, link targets, and markup from prose.
fn visible_text(text: &str) -> String {
    let mut result = String::new();
    let mut characters = text.chars().peekable();
    let mut code = false;
    let mut quote = false;
    let mut tag = false;
    while let Some(character) = characters.next() {
        if tag {
            if character == '>' {
                tag = false;
                result.push(' ');
            }
            continue;
        }
        if !code && !quote && character == '<' {
            tag = true;
            continue;
        }
        if !quote && character == '`' {
            code = !code;
            if !code {
                result.push_str(" CODE ");
            }
            continue;
        }
        if !code && character == '"' {
            quote = !quote;
            if !quote {
                result.push_str(" QUOTE ");
            }
            continue;
        }
        if code || quote {
            continue;
        }
        if character == ']' && characters.peek() == Some(&'(') {
            characters.next();
            for next in characters.by_ref() {
                if next == ')' {
                    break;
                }
            }
            result.push(' ');
            continue;
        }
        result.push(character);
    }
    result
}

/// Splits prose into sentence slices.
fn split_sentences(text: &str) -> Vec<&str> {
    let mut sentences = Vec::new();
    let mut start = 0;
    for (index, character) in text.char_indices() {
        if !matches!(character, '.' | '!' | '?') {
            continue;
        }
        let end = index + character.len_utf8();
        if text[end..]
            .chars()
            .next()
            .is_some_and(|next| !next.is_whitespace())
        {
            continue;
        }
        let sentence = text[start..end].trim();
        if !sentence.is_empty() {
            sentences.push(sentence);
        }
        start = end;
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        sentences.push(tail);
    }
    sentences
}

/// Returns lowercase words and preserves internal hyphens and apostrophes.
fn words(text: &str) -> Vec<String> {
    text.split(|character: char| {
        !character.is_ascii_alphabetic() && character != '-' && character != '\''
    })
    .filter(|word| {
        !word.is_empty()
            && word
                .chars()
                .any(|character| character.is_ascii_alphabetic())
    })
    .map(|word| word.trim_matches(['-', '\'']).to_ascii_lowercase())
    .filter(|word| !word.is_empty())
    .collect()
}

/// Returns `true` if `words` contains all words of `phrase` in sequence.
fn contains_phrase(words: &[String], phrase: &str) -> bool {
    let phrase_words = phrase.split_whitespace().collect::<Vec<_>>();
    words.windows(phrase_words.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(phrase_words.iter().copied())
    })
}

/// Adds one violation to the result.
fn add_violation(path: &Path, line: usize, message: String, violations: &mut Vec<Violation>) {
    violations.push(Violation {
        path: path.to_path_buf(),
        line,
        message,
    });
}
