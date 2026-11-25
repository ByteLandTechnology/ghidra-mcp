// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Linear-time regular expression evaluation for cached string queries.
//!
//! The daemon evaluates regular expression queries on persisted string snapshots
//! without a cold Ghidra scan. Patterns with Java lookarounds or backreferences
//! return [`RegexError::Unsupported`] so the caller delegates to the bridge.

mod parser;

use parser::{Expr, Parser};
use std::ops::RangeInclusive;

/// An error from regular expression compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexError {
    /// The pattern has invalid regular expression syntax.
    Invalid(String),
    /// The pattern uses a construct that requires the Java regular expression engine.
    Unsupported,
}

/// A compiled unanchored regular expression matcher.
#[derive(Debug, Clone)]
pub struct CompiledRegex {
    /// The Thompson NFA instructions.
    instructions: Vec<Inst>,
    /// The start state index.
    start: usize,
}

/// One character class item.
#[derive(Debug, Clone)]
pub(super) enum ClassAtom {
    /// One character or a folded character range.
    Range(RangeInclusive<char>),
    /// Decimal digits (`\d` or `\D`).
    Digit(bool),
    /// Word characters (`\w` or `\W`).
    Word(bool),
    /// Whitespace characters (`\s` or `\S`).
    Space(bool),
}

/// Zero-width assertion types.
#[derive(Debug, Clone, Copy)]
pub(super) enum Anchor {
    /// Start of input (`^` or `\A`).
    Start,
    /// End of input (`$` or `\z`).
    End,
    /// Word boundary (`\b`).
    WordBoundary,
    /// Non-word boundary (`\B`).
    NonWordBoundary,
}

/// One NFA instruction.
#[derive(Debug, Clone)]
enum Inst {
    /// Checks one literal character, with optional case conversion.
    Char {
        /// Expected character value.
        expected: char,
        /// `true` when case differences do not matter.
        fold_case: bool,
    },
    /// Accepts any character except `\n` and `\r`.
    AnyNoNewline,
    /// Checks a character class.
    Class {
        /// `true` for a negated class (`[^...]`).
        negated: bool,
        /// `true` when case differences do not matter.
        fold_case: bool,
        /// Character class items.
        atoms: Vec<ClassAtom>,
    },
    /// Checks a zero-width boundary assertion.
    Assert(Anchor),
    /// Unconditional transition to target instruction.
    Jump(usize),
    /// Epsilon split to two target instructions.
    Split(usize, usize),
    /// Accepts the match.
    Match,
}

impl CompiledRegex {
    /// Compiles `pattern` for unanchored regular expression evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::Invalid`] for malformed regular expression syntax and
    /// [`RegexError::Unsupported`] for Java lookaround or backreference syntax.
    pub fn compile(pattern: &str, case_sensitive: bool) -> Result<Self, RegexError> {
        let mut parser = Parser::new(pattern, !case_sensitive);
        let ast = parser.parse_alternation()?;
        if parser.peek().is_some() {
            return Err(RegexError::Invalid("unmatched right parenthesis".into()));
        }
        let mut compiler = Compiler {
            instructions: Vec::new(),
        };
        let start = compiler.compile_expr(&ast);
        let match_state = compiler.emit(Inst::Match);
        compiler.patch_slots(start.exits, match_state);
        Ok(Self {
            instructions: compiler.instructions,
            start: start.entry,
        })
    }

    /// Returns `true` if `haystack` contains a match for this regular expression.
    pub fn is_match(&self, haystack: &str) -> bool {
        let chars: Vec<char> = haystack.chars().collect();
        let count = self.instructions.len();
        let mut current = StateSet::new(count);
        let mut next = StateSet::new(count);

        for start_pos in 0..=chars.len() {
            self.add_state(&mut current, self.start, &chars, start_pos);
            if current.contains_match(&self.instructions) {
                return true;
            }
            if start_pos == chars.len() {
                break;
            }
            let ch = chars[start_pos];
            next.clear();
            let active: Vec<usize> = current.list.clone();
            for state in active {
                if let Some(target) = self.step_char(state, ch) {
                    self.add_state(&mut next, target, &chars, start_pos + 1);
                }
            }
            std::mem::swap(&mut current, &mut next);
            if current.contains_match(&self.instructions) {
                return true;
            }
        }
        false
    }

    /// Evaluates one character transition from `state` on `ch`.
    fn step_char(&self, state: usize, ch: char) -> Option<usize> {
        match &self.instructions[state] {
            Inst::Char {
                expected,
                fold_case,
            } => chars_equal(*expected, ch, *fold_case).then_some(state + 1),
            Inst::AnyNoNewline => (ch != '\n' && ch != '\r').then_some(state + 1),
            Inst::Class {
                negated,
                fold_case,
                atoms,
            } => {
                let matched = atoms.iter().any(|atom| atom_matches(atom, ch, *fold_case));
                (matched != *negated).then_some(state + 1)
            }
            _ => None,
        }
    }

    /// Inserts `state` and its epsilon closure at `pos` into `set`.
    fn add_state(&self, set: &mut StateSet, state: usize, chars: &[char], pos: usize) {
        if !set.insert(state) {
            return;
        }
        match &self.instructions[state] {
            Inst::Jump(target) => self.add_state(set, *target, chars, pos),
            Inst::Split(first, second) => {
                self.add_state(set, *first, chars, pos);
                self.add_state(set, *second, chars, pos);
            }
            Inst::Assert(anchor) if anchor_holds(*anchor, chars, pos) => {
                self.add_state(set, state + 1, chars, pos);
            }
            _ => {}
        }
    }
}

/// Active NFA state set with sparse membership flags.
struct StateSet {
    /// Active state indices in insertion order.
    list: Vec<usize>,
    /// Membership flags indexed by state number.
    present: Vec<bool>,
}

impl StateSet {
    /// Creates an empty state set for an NFA with `size` states.
    fn new(size: usize) -> Self {
        Self {
            list: Vec::with_capacity(size),
            present: vec![false; size],
        }
    }

    /// Clears all active states.
    fn clear(&mut self) {
        for &idx in &self.list {
            self.present[idx] = false;
        }
        self.list.clear();
    }

    /// Inserts `state` if it is absent. Returns `true` when added.
    fn insert(&mut self, state: usize) -> bool {
        if self.present[state] {
            return false;
        }
        self.present[state] = true;
        self.list.push(state);
        true
    }

    /// Returns `true` if the set holds [`Inst::Match`].
    fn contains_match(&self, instructions: &[Inst]) -> bool {
        self.list
            .iter()
            .any(|&idx| matches!(instructions[idx], Inst::Match))
    }
}

/// Half-compiled NFA fragment.
struct Fragment {
    /// Entry state index.
    entry: usize,
    /// Open transitions that wait for a target state.
    exits: Vec<PatchSlot>,
}

/// Identifies an instruction slot that needs its target state index filled in.
#[derive(Clone, Copy)]
enum PatchSlot {
    /// Target of [`Inst::Jump`].
    Jump(usize),
    /// Second branch of [`Inst::Split`].
    SplitSecond(usize),
}

/// Thompson NFA compiler.
struct Compiler {
    /// Emitted NFA instructions.
    instructions: Vec<Inst>,
}

impl Compiler {
    /// Appends `inst` and returns its index.
    fn emit(&mut self, inst: Inst) -> usize {
        let index = self.instructions.len();
        self.instructions.push(inst);
        index
    }

    /// Updates every slot in `slots` to point at `target`.
    fn patch_slots(&mut self, slots: Vec<PatchSlot>, target: usize) {
        for slot in slots {
            match slot {
                PatchSlot::Jump(idx) => self.instructions[idx] = Inst::Jump(target),
                PatchSlot::SplitSecond(idx) => {
                    if let Inst::Split(_, second) = &mut self.instructions[idx] {
                        *second = target;
                    }
                }
            }
        }
    }

    /// Compiles one AST expression into an NFA fragment.
    fn compile_expr(&mut self, expr: &Expr) -> Fragment {
        match expr {
            Expr::Empty => {
                let idx = self.emit(Inst::Jump(0));
                Fragment {
                    entry: idx,
                    exits: vec![PatchSlot::Jump(idx)],
                }
            }
            Expr::Literal { ch, fold_case } => self.compile_step(Inst::Char {
                expected: *ch,
                fold_case: *fold_case,
            }),
            Expr::Dot => self.compile_step(Inst::AnyNoNewline),
            Expr::Class {
                negated,
                fold_case,
                atoms,
            } => self.compile_step(Inst::Class {
                negated: *negated,
                fold_case: *fold_case,
                atoms: atoms.clone(),
            }),
            Expr::Anchor(anchor) => self.compile_step(Inst::Assert(*anchor)),
            Expr::Concat(items) => {
                let mut iter = items.iter();
                let Some(first_expr) = iter.next() else {
                    return self.compile_expr(&Expr::Empty);
                };
                let mut frag = self.compile_expr(first_expr);
                for next_expr in iter {
                    let next_frag = self.compile_expr(next_expr);
                    self.patch_slots(frag.exits, next_frag.entry);
                    frag.exits = next_frag.exits;
                }
                frag
            }
            Expr::Alt(left, right) => {
                let split = self.emit(Inst::Split(0, 0));
                let left_frag = self.compile_expr(left);
                let right_frag = self.compile_expr(right);
                self.instructions[split] = Inst::Split(left_frag.entry, right_frag.entry);
                let mut exits = left_frag.exits;
                exits.extend(right_frag.exits);
                Fragment {
                    entry: split,
                    exits,
                }
            }
            Expr::Repeat { inner, min, max } => self.compile_repeat(inner, *min, *max),
        }
    }

    /// Emits a single step instruction followed by an unpatched jump.
    fn compile_step(&mut self, step: Inst) -> Fragment {
        let entry = self.emit(step);
        let jump = self.emit(Inst::Jump(0));
        Fragment {
            entry,
            exits: vec![PatchSlot::Jump(jump)],
        }
    }

    /// Compiles bounded or unbounded repetition `{min, max}`.
    fn compile_repeat(&mut self, inner: &Expr, min: usize, max: Option<usize>) -> Fragment {
        let mut parts = Vec::new();
        for _ in 0..min {
            parts.push(self.compile_expr(inner));
        }
        match max {
            None => parts.push(self.compile_zero_or_more(inner)),
            Some(upper) => {
                for _ in min..upper {
                    parts.push(self.compile_optional(inner));
                }
            }
        }
        let mut iter = parts.into_iter();
        let Some(mut acc) = iter.next() else {
            return self.compile_expr(&Expr::Empty);
        };
        for next in iter {
            self.patch_slots(acc.exits, next.entry);
            acc.exits = next.exits;
        }
        acc
    }

    /// Compiles `inner?`.
    fn compile_optional(&mut self, inner: &Expr) -> Fragment {
        let split = self.emit(Inst::Split(0, 0));
        let sub = self.compile_expr(inner);
        self.instructions[split] = Inst::Split(sub.entry, 0);
        let mut exits = sub.exits;
        exits.push(PatchSlot::SplitSecond(split));
        Fragment {
            entry: split,
            exits,
        }
    }

    /// Compiles `inner*`.
    fn compile_zero_or_more(&mut self, inner: &Expr) -> Fragment {
        let split = self.emit(Inst::Split(0, 0));
        let sub = self.compile_expr(inner);
        self.instructions[split] = Inst::Split(sub.entry, 0);
        self.patch_slots(sub.exits, split);
        Fragment {
            entry: split,
            exits: vec![PatchSlot::SplitSecond(split)],
        }
    }
}

/// Compares two characters, with optional case conversion.
fn chars_equal(expected: char, actual: char, fold_case: bool) -> bool {
    if expected == actual {
        return true;
    }
    if !fold_case {
        return false;
    }
    if expected.is_ascii() && actual.is_ascii() {
        return expected.eq_ignore_ascii_case(&actual);
    }
    expected.to_lowercase().eq(actual.to_lowercase())
}

/// Evaluates one character class atom against `ch`.
fn atom_matches(atom: &ClassAtom, ch: char, fold_case: bool) -> bool {
    match atom {
        ClassAtom::Range(range) => {
            if range.contains(&ch) {
                return true;
            }
            if !fold_case {
                return false;
            }
            if ch.is_ascii() {
                let lower = ch.to_ascii_lowercase();
                let upper = ch.to_ascii_uppercase();
                return range.contains(&lower) || range.contains(&upper);
            }
            ch.to_lowercase().any(|lower| range.contains(&lower))
                || ch.to_uppercase().any(|upper| range.contains(&upper))
        }
        ClassAtom::Digit(positive) => ch.is_ascii_digit() == *positive,
        ClassAtom::Word(positive) => is_word_char(ch) == *positive,
        ClassAtom::Space(positive) => ch.is_ascii_whitespace() == *positive,
    }
}

/// Returns `true` for ASCII word characters (`[A-Za-z0-9_]`).
fn is_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// Evaluates a zero-width anchor at `pos` in `chars`.
fn anchor_holds(anchor: Anchor, chars: &[char], pos: usize) -> bool {
    match anchor {
        Anchor::Start => pos == 0,
        Anchor::End => pos == chars.len(),
        Anchor::WordBoundary => is_word_boundary(chars, pos),
        Anchor::NonWordBoundary => !is_word_boundary(chars, pos),
    }
}

/// Returns `true` if `pos` sits on a word boundary in `chars`.
fn is_word_boundary(chars: &[char], pos: usize) -> bool {
    let left = pos
        .checked_sub(1)
        .and_then(|idx| chars.get(idx))
        .is_some_and(|&ch| is_word_char(ch));
    let right = chars.get(pos).is_some_and(|&ch| is_word_char(ch));
    left != right
}

#[cfg(test)]
mod tests {
    use super::{CompiledRegex, RegexError};

    /// Checks literal, case-insensitive, character class, anchor, and quantifier behavior.
    #[test]
    fn matches_common_agent_patterns() {
        let url = CompiledRegex::compile("https?://[a-z0-9.-]+/api/v\\d+", false).unwrap();
        assert!(url.is_match("POST https://Example.COM/api/v2/login"));
        assert!(!url.is_match("ftp://example.com/api/v2"));

        let exact = CompiledRegex::compile("^HKEY_LOCAL_MACHINE\\\\Software$", true).unwrap();
        assert!(exact.is_match("HKEY_LOCAL_MACHINE\\Software"));
        assert!(!exact.is_match("hkey_local_machine\\software"));

        let inline = CompiledRegex::compile("(?i)bearer\\s+[a-f0-9]{4,8}\\b", true).unwrap();
        assert!(inline.is_match("Authorization: Bearer deadbeef"));
        assert!(!inline.is_match("Authorization: Bearer deadbeef00"));
    }

    /// Checks syntax error and unsupported Java construct classification.
    #[test]
    fn classifies_invalid_and_java_specific_patterns() {
        assert!(matches!(
            CompiledRegex::compile("[unclosed", true),
            Err(RegexError::Invalid(_))
        ));
        assert!(matches!(
            CompiledRegex::compile("*prefix", true),
            Err(RegexError::Invalid(_))
        ));
        assert_eq!(
            CompiledRegex::compile("foo(?=bar)", true).unwrap_err(),
            RegexError::Unsupported
        );
    }
}
