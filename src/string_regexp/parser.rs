// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Recursive-descent regular expression parser for [`super::CompiledRegex`].

use super::{Anchor, ClassAtom, RegexError};

/// Maximum quantifier expansion bound to keep memory use small.
const MAX_REPEAT_BOUND: usize = 256;

/// AST node produced by the recursive-descent parser.
#[derive(Debug, Clone)]
pub(super) enum Expr {
    /// Accepts empty text.
    Empty,
    /// Literal character.
    Literal {
        /// Expected character value.
        ch: char,
        /// `true` when case differences do not matter.
        fold_case: bool,
    },
    /// Dot wildcard.
    Dot,
    /// Character class.
    Class {
        /// `true` for a negated class.
        negated: bool,
        /// `true` when case differences do not matter.
        fold_case: bool,
        /// Class items.
        atoms: Vec<ClassAtom>,
    },
    /// Zero-width assertion.
    Anchor(Anchor),
    /// Sequence of expressions.
    Concat(Vec<Expr>),
    /// Alternation of two expressions.
    Alt(Box<Expr>, Box<Expr>),
    /// Bounded or unbounded repetition.
    Repeat {
        /// Repeated subexpression.
        inner: Box<Expr>,
        /// Minimum count.
        min: usize,
        /// Optional maximum count.
        max: Option<usize>,
    },
}

/// Intermediate character class item.
enum ClassItem {
    /// Single character that can form a `start-end` range.
    Char(char),
    /// Predefined character class escape.
    Atom(ClassAtom),
}

/// Recursive-descent regular expression parser.
pub(super) struct Parser {
    /// Input pattern characters.
    chars: Vec<char>,
    /// Current cursor index.
    pos: usize,
    /// Current case-fold flag.
    fold_case: bool,
}

impl Parser {
    /// Creates a parser for `pattern`.
    pub(super) fn new(pattern: &str, fold_case: bool) -> Self {
        Self {
            chars: pattern.chars().collect(),
            pos: 0,
            fold_case,
        }
    }

    /// Returns the character at the current position without an advance.
    pub(super) fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    /// Consumes and returns the character at the current position.
    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    /// Parses `expr ('|' expr)*`.
    pub(super) fn parse_alternation(&mut self) -> Result<Expr, RegexError> {
        let mut left = self.parse_concat()?;
        while self.peek() == Some('|') {
            self.pos += 1;
            let right = self.parse_concat()?;
            left = Expr::Alt(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// Parses a sequence of quantified atoms until `)`, `|`, or end of input.
    fn parse_concat(&mut self) -> Result<Expr, RegexError> {
        let mut parts = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == ')' || ch == '|' {
                break;
            }
            if let Some(atom) = self.parse_atom()? {
                let quantified = self.parse_quantifier(atom)?;
                parts.push(quantified);
            }
        }
        Ok(match parts.len() {
            0 => Expr::Empty,
            1 => parts.pop().unwrap_or(Expr::Empty),
            _ => Expr::Concat(parts),
        })
    }

    /// Parses one atom or inline flag group. Returns `None` when an inline flag
    /// toggle such as `(?i)` updates parser state without a new atom.
    fn parse_atom(&mut self) -> Result<Option<Expr>, RegexError> {
        let Some(ch) = self.next_char() else {
            return Ok(None);
        };
        match ch {
            '*' | '+' | '?' => Err(RegexError::Invalid(format!("unattached quantifier `{ch}`"))),
            '{' => Err(RegexError::Invalid("unattached `{` quantifier".into())),
            '.' => Ok(Some(Expr::Dot)),
            '^' => Ok(Some(Expr::Anchor(Anchor::Start))),
            '$' => Ok(Some(Expr::Anchor(Anchor::End))),
            '[' => self.parse_class().map(Some),
            '(' => self.parse_group(),
            '\\' => self.parse_escape().map(Some),
            other => Ok(Some(Expr::Literal {
                ch: other,
                fold_case: self.fold_case,
            })),
        }
    }

    /// Parses `(...)`, `(?:...)`, `(?i)`, `(?-i)`, or `(?:...)` with inline flags.
    fn parse_group(&mut self) -> Result<Option<Expr>, RegexError> {
        if self.peek() == Some('?') {
            self.pos += 1;
            let saved_fold = self.fold_case;
            let mut local_fold = saved_fold;
            let mut saw_flag = false;
            let mut negate = false;
            while let Some(flag) = self.peek() {
                match flag {
                    '-' => {
                        negate = true;
                        saw_flag = true;
                        self.pos += 1;
                    }
                    'i' => {
                        local_fold = !negate;
                        saw_flag = true;
                        self.pos += 1;
                    }
                    ')' if saw_flag => {
                        self.pos += 1;
                        self.fold_case = local_fold;
                        return Ok(None);
                    }
                    ':' => {
                        self.pos += 1;
                        self.fold_case = local_fold;
                        let inner = self.parse_alternation()?;
                        self.fold_case = saved_fold;
                        if self.next_char() != Some(')') {
                            return Err(RegexError::Invalid("unclosed group".into()));
                        }
                        return Ok(Some(inner));
                    }
                    _ => return Err(RegexError::Unsupported),
                }
            }
            return Err(RegexError::Invalid("unclosed group".into()));
        }
        let inner = self.parse_alternation()?;
        if self.next_char() != Some(')') {
            return Err(RegexError::Invalid("unclosed group".into()));
        }
        Ok(Some(inner))
    }

    /// Parses an escape sequence after `\`.
    fn parse_escape(&mut self) -> Result<Expr, RegexError> {
        let Some(ch) = self.next_char() else {
            return Err(RegexError::Invalid("incomplete backslash escape".into()));
        };
        match ch {
            'd' => Ok(Expr::Class {
                negated: false,
                fold_case: false,
                atoms: vec![ClassAtom::Digit(true)],
            }),
            'D' => Ok(Expr::Class {
                negated: false,
                fold_case: false,
                atoms: vec![ClassAtom::Digit(false)],
            }),
            'w' => Ok(Expr::Class {
                negated: false,
                fold_case: false,
                atoms: vec![ClassAtom::Word(true)],
            }),
            'W' => Ok(Expr::Class {
                negated: false,
                fold_case: false,
                atoms: vec![ClassAtom::Word(false)],
            }),
            's' => Ok(Expr::Class {
                negated: false,
                fold_case: false,
                atoms: vec![ClassAtom::Space(true)],
            }),
            'S' => Ok(Expr::Class {
                negated: false,
                fold_case: false,
                atoms: vec![ClassAtom::Space(false)],
            }),
            'b' => Ok(Expr::Anchor(Anchor::WordBoundary)),
            'B' => Ok(Expr::Anchor(Anchor::NonWordBoundary)),
            'A' => Ok(Expr::Anchor(Anchor::Start)),
            'z' => Ok(Expr::Anchor(Anchor::End)),
            'Z' | 'G' | 'p' | 'P' | '1'..='9' | 'k' => Err(RegexError::Unsupported),
            'Q' => Ok(self.parse_quoted_literal()),
            't' => Ok(Expr::Literal {
                ch: '\t',
                fold_case: false,
            }),
            'n' => Ok(Expr::Literal {
                ch: '\n',
                fold_case: false,
            }),
            'r' => Ok(Expr::Literal {
                ch: '\r',
                fold_case: false,
            }),
            'f' => Ok(Expr::Literal {
                ch: '\u{000c}',
                fold_case: false,
            }),
            'a' => Ok(Expr::Literal {
                ch: '\u{0007}',
                fold_case: false,
            }),
            'e' => Ok(Expr::Literal {
                ch: '\u{001b}',
                fold_case: false,
            }),
            'x' => {
                let code = self.parse_hex_escape(2)?;
                Ok(Expr::Literal {
                    ch: code,
                    fold_case: self.fold_case,
                })
            }
            'u' => {
                let code = self.parse_hex_escape(4)?;
                Ok(Expr::Literal {
                    ch: code,
                    fold_case: self.fold_case,
                })
            }
            other if other.is_ascii_alphabetic() => Err(RegexError::Invalid(format!(
                "unsupported escape `\\{other}`"
            ))),
            other => Ok(Expr::Literal {
                ch: other,
                fold_case: self.fold_case,
            }),
        }
    }

    /// Parses `\Q...\E` literal quotation.
    fn parse_quoted_literal(&mut self) -> Expr {
        let mut literals = Vec::new();
        while let Some(ch) = self.next_char() {
            if ch == '\\' && self.peek() == Some('E') {
                self.pos += 1;
                break;
            }
            literals.push(Expr::Literal {
                ch,
                fold_case: self.fold_case,
            });
        }
        match literals.len() {
            0 => Expr::Empty,
            1 => literals.pop().unwrap_or(Expr::Empty),
            _ => Expr::Concat(literals),
        }
    }

    /// Parses a fixed-width hex escape (`\xHH` or `\uXXXX`).
    fn parse_hex_escape(&mut self, digits: usize) -> Result<char, RegexError> {
        let mut value = 0u32;
        for _ in 0..digits {
            let Some(ch) = self.next_char() else {
                return Err(RegexError::Invalid("incomplete hex escape".into()));
            };
            let Some(digit) = ch.to_digit(16) else {
                return Err(RegexError::Invalid("invalid hex escape digit".into()));
            };
            value = (value << 4) | digit;
        }
        char::from_u32(value).ok_or_else(|| RegexError::Invalid("invalid Unicode scalar".into()))
    }

    /// Parses `[...]` character classes.
    fn parse_class(&mut self) -> Result<Expr, RegexError> {
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut atoms = Vec::new();
        let mut first = true;
        while let Some(ch) = self.peek() {
            if ch == ']' && !first {
                self.pos += 1;
                return Ok(Expr::Class {
                    negated,
                    fold_case: self.fold_case,
                    atoms,
                });
            }
            first = false;
            if ch == '[' {
                return Err(RegexError::Unsupported);
            }
            let item = self.parse_class_item()?;
            if let ClassItem::Char(start) = item {
                if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                    self.pos += 1;
                    let ClassItem::Char(end) = self.parse_class_item()? else {
                        return Err(RegexError::Invalid("invalid character class range".into()));
                    };
                    if start > end {
                        return Err(RegexError::Invalid(
                            "character class range is out of order".into(),
                        ));
                    }
                    atoms.push(ClassAtom::Range(start..=end));
                    continue;
                }
                atoms.push(ClassAtom::Range(start..=start));
            } else if let ClassItem::Atom(atom) = item {
                atoms.push(atom);
            }
        }
        Err(RegexError::Invalid("unclosed character class".into()))
    }

    /// Parses one item inside `[...]`.
    fn parse_class_item(&mut self) -> Result<ClassItem, RegexError> {
        let Some(ch) = self.next_char() else {
            return Err(RegexError::Invalid("unclosed character class".into()));
        };
        if ch != '\\' {
            return Ok(ClassItem::Char(ch));
        }
        let Some(escaped) = self.next_char() else {
            return Err(RegexError::Invalid("incomplete backslash in class".into()));
        };
        match escaped {
            'd' => Ok(ClassItem::Atom(ClassAtom::Digit(true))),
            'D' => Ok(ClassItem::Atom(ClassAtom::Digit(false))),
            'w' => Ok(ClassItem::Atom(ClassAtom::Word(true))),
            'W' => Ok(ClassItem::Atom(ClassAtom::Word(false))),
            's' => Ok(ClassItem::Atom(ClassAtom::Space(true))),
            'S' => Ok(ClassItem::Atom(ClassAtom::Space(false))),
            't' => Ok(ClassItem::Char('\t')),
            'n' => Ok(ClassItem::Char('\n')),
            'r' => Ok(ClassItem::Char('\r')),
            'f' => Ok(ClassItem::Char('\u{000c}')),
            'a' => Ok(ClassItem::Char('\u{0007}')),
            'e' => Ok(ClassItem::Char('\u{001b}')),
            'x' => self.parse_hex_escape(2).map(ClassItem::Char),
            'u' => self.parse_hex_escape(4).map(ClassItem::Char),
            'p' | 'P' => Err(RegexError::Unsupported),
            other if other.is_ascii_alphabetic() => Err(RegexError::Invalid(format!(
                "unsupported class escape `\\{other}`"
            ))),
            other => Ok(ClassItem::Char(other)),
        }
    }

    /// Parses optional quantifiers (`*`, `+`, `?`, `{m,n}`) and modifier suffixes.
    fn parse_quantifier(&mut self, atom: Expr) -> Result<Expr, RegexError> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => {
                self.pos += 1;
                self.parse_braced_bounds()?
            }
            _ => return Ok(atom),
        };
        if matches!(atom, Expr::Anchor(_)) {
            return Err(RegexError::Invalid("quantifier on anchor".into()));
        }
        match self.peek() {
            Some('?') => {
                self.pos += 1;
            }
            Some('+') => return Err(RegexError::Unsupported),
            _ => {}
        }
        if matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
            return Err(RegexError::Invalid("nested quantifier".into()));
        }
        Ok(Expr::Repeat {
            inner: Box::new(atom),
            min,
            max,
        })
    }

    /// Parses `m}`, `m,}`, or `m,n}` after `{`.
    fn parse_braced_bounds(&mut self) -> Result<(usize, Option<usize>), RegexError> {
        let min = self.parse_decimal()?;
        let max = if self.peek() == Some(',') {
            self.pos += 1;
            if self.peek() == Some('}') {
                None
            } else {
                Some(self.parse_decimal()?)
            }
        } else {
            Some(min)
        };
        if self.next_char() != Some('}') {
            return Err(RegexError::Invalid("unclosed `{m,n}` quantifier".into()));
        }
        if let Some(upper) = max {
            if upper < min {
                return Err(RegexError::Invalid(
                    "quantifier maximum is smaller than minimum".into(),
                ));
            }
            if upper > MAX_REPEAT_BOUND {
                return Err(RegexError::Unsupported);
            }
        }
        if min > MAX_REPEAT_BOUND {
            return Err(RegexError::Unsupported);
        }
        Ok((min, max))
    }

    /// Parses one non-empty decimal integer inside `{...}`.
    fn parse_decimal(&mut self) -> Result<usize, RegexError> {
        let start = self.pos;
        let mut value = 0usize;
        while let Some(ch) = self.peek() {
            let Some(digit) = ch.to_digit(10) else {
                break;
            };
            self.pos += 1;
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit as usize))
                .ok_or_else(|| RegexError::Invalid("quantifier bound overflow".into()))?;
        }
        if self.pos == start {
            return Err(RegexError::Invalid("expected integer in `{...}`".into()));
        }
        Ok(value)
    }
}
