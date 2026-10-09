//! Cracker attack modes and the worker threads driving them.
//!
//! Everything here runs in the UI process — the candidates and the GPU
//! need no privileges and **no radio**: wordlist / brute-force candidates
//! go through PBKDF2 (GPU when an adapter exists, CPU fallback), a rainbow
//! table ([`crate::rainbow`]) skips PBKDF2 entirely and checks precomputed
//! PMKs with one PTK derivation + MIC compare each.
//!
//! Worker contract (unchanged from the old service-coupled cracker):
//! progress via `CrackProgress`, then exactly one terminator —
//! `CrackFound` + `CrackStopped { found: true }` on success,
//! `CrackStopped { found: false }` on stop, exhaustion, or setup failure.
//! The rainbow *builder* job reports `RainbowProgress` and always ends
//! with one `RainbowBuilt` (entries written so far; errors precede it as
//! `Error` events).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use crossbeam_channel::Sender;

use crate::common::Event;
use crate::crypto::{self, CrackTarget};
use crate::gpu::{self, GpuCracker};
use crate::rainbow;
use crate::store;
use crate::wordlist;

/// Attack mode selected on the Cracker page. Serialized into the resume
/// session file (see [`crate::store::CrackSession`]) exactly as entered.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Attack {
    /// Dictionary: stream a wordlist through PBKDF2.
    Wordlist(PathBuf),
    /// Dictionary × mutation rules (hashcat-subset ops, see [`parse_rules`]).
    Rules { wordlist: PathBuf, rules: PathBuf },
    /// Dictionary × append-charset sweep: `word + charset^k` for k in `min..=max`.
    Hybrid { wordlist: PathBuf, charset: Vec<u8>, min: usize, max: usize },
    /// Exhaustive `charset^len` sweep for len in `min..=max` through PBKDF2.
    /// `freq_order` permutes the charset most-common-first (a bijection —
    /// space size and seek indices are unchanged).
    Bruteforce {
        charset: Vec<u8>,
        min: usize,
        max: usize,
        #[serde(default)]
        freq_order: bool,
    },
    /// Precomputed PMK table for the target SSID — no PBKDF2 at run time.
    Rainbow(PathBuf),
}

impl Attack {
    /// One line for logs/status.
    pub fn describe(&self) -> String {
        match self {
            Attack::Wordlist(p) => format!("wordlist {}", p.display()),
            Attack::Rules { wordlist, rules } => {
                format!("rules {} × {}", wordlist.display(), rules.display())
            }
            Attack::Hybrid { wordlist, charset, min, max } => format!(
                "hybrid {} + charset({} bytes) suffix len {min}..={max}",
                wordlist.display(),
                charset.len()
            ),
            Attack::Bruteforce { charset, min, max, freq_order } => format!(
                "bruteforce charset({} bytes, {:?}…{}) len {min}..={max}",
                charset.len(),
                String::from_utf8_lossy(&charset[..charset.len().min(16)]),
                if *freq_order { ", freq-order" } else { "" },
            ),
            Attack::Rainbow(p) => format!("rainbow {}", p.display()),
        }
    }

    /// Fail-fast validation the UI runs BEFORE marking a run active, so a
    /// refused start never leaves stale running flags or a zombie thread.
    pub fn validate(&self) -> Result<()> {
        match self {
            Attack::Wordlist(p) => {
                std::fs::File::open(p)
                    .with_context(|| format!("cannot open wordlist {}", p.display()))?;
            }
            Attack::Rules { wordlist, rules } => {
                std::fs::File::open(wordlist)
                    .with_context(|| format!("cannot open wordlist {}", wordlist.display()))?;
                let parsed = parse_rules(rules)
                    .with_context(|| format!("cannot parse rules file {}", rules.display()))?;
                if parsed.is_empty() {
                    bail!("rules file {} has no rules", rules.display());
                }
            }
            Attack::Hybrid { wordlist, charset, min, max } => {
                std::fs::File::open(wordlist)
                    .with_context(|| format!("cannot open wordlist {}", wordlist.display()))?;
                HybridIter::validate(charset, *min, *max)?;
            }
            Attack::Bruteforce { charset, min, max, freq_order } => {
                BruteForce::new(charset.clone(), *min, *max, *freq_order).map(|_| ())?;
            }
            Attack::Rainbow(p) => {
                std::fs::File::open(p)
                    .with_context(|| format!("cannot open PMK table {}", p.display()))?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Charset presets (Cracker page bruteforce chips) + custom input
// ---------------------------------------------------------------------------

/// Predefined charsets the UI offers as toggle chips; the effective
/// brute-force charset is the union of the checked presets and the
/// custom field. Keep SPECIAL to the commonly used symbols — exotic
/// bytes belong in the custom field.
pub mod charset {
    pub const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    pub const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    pub const DIGITS: &[u8] = b"0123456789";
    pub const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>/?";

    /// Union of the selected presets + `custom`, deduplicated.
    pub fn compose(lower: bool, upper: bool, digits: bool, special: bool, custom: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for src in [
            (lower, LOWER),
            (upper, UPPER),
            (digits, DIGITS),
            (special, SPECIAL),
        ] {
            if src.0 {
                out.extend_from_slice(src.1);
            }
        }
        out.extend_from_slice(custom);
        out.sort_unstable();
        out.dedup();
        out
    }
}

// ---------------------------------------------------------------------------
// Brute-force candidate generator
// ---------------------------------------------------------------------------

/// password-frequency heuristic: most-common characters first; the
/// odometer still varies the right-most position fastest.
const FREQ_ORDER: &[u8] = b"e1a0ir7o29nls38tc45um6!dpghwyb$vkfxqjz@EAOINSRHLTCDUMPFGYKWBVJXQZ#._-";

/// Streaming `charset^len` generator for len in min..=max, clamped to the
/// WPA passphrase range 8..=63. Odometer order: right-most position cycles
/// fastest, words of one length exhaust before the next length starts.
/// With `freq_order` the charset is permuted by [`FREQ_ORDER`] rank
/// (chars absent from it keep codepoint order, appended after) — a
/// bijection, so `space()` size and `seek()` indices are unchanged.
pub struct BruteForce {
    charset: Vec<u8>,
    /// Clamped minimum length (the space starts here).
    min_len: usize,
    /// Current word length.
    len: usize,
    max_len: usize,
    /// Odometer digits (indices into charset), same length as the word.
    idx: Vec<usize>,
    exhausted: bool,
}

impl BruteForce {
    /// `Err` when the charset is empty or the clamped length range is empty
    /// (nothing 8..=63-compatible to try).
    pub fn new(charset: Vec<u8>, min: usize, max: usize, freq_order: bool) -> Result<Self> {
        let mut charset = charset;
        if freq_order {
            let rank = |b: u8| FREQ_ORDER.iter().position(|&c| c == b).unwrap_or(usize::MAX);
            charset.sort_by_key(|&b| (rank(b), b));
            charset.dedup();
        } else {
            charset.dedup();
        }
        if charset.is_empty() {
            bail!("bruteforce: charset is empty");
        }
        // Intersect with the WPA passphrase range instead of clamping
        // both bounds: 64..=70 must be rejected (empty intersection), not
        // silently turned into 63..=63.
        let lo = min.max(8);
        let hi = max.min(63);
        if lo > hi {
            bail!("bruteforce: length range {min}..={max} has no WPA-legal lengths (8..=63)");
        }
        Ok(BruteForce {
            charset,
            min_len: lo,
            len: lo,
            max_len: hi,
            idx: vec![0; lo],
            exhausted: false,
        })
    }

    /// Total candidate count over the whole length range (may exceed u64;
    /// used for logs only).
    pub fn space(&self) -> u128 {
        let base = self.charset.len() as u128;
        (self.len..=self.max_len).map(|l| base.pow(l as u32)).sum()
    }

    /// Jump the odometer so the NEXT [`next`] yields candidate number `n`
    /// (0-based) of the full space — the resume path. `n` beyond the space
    /// exhausts the generator.
    pub fn seek(&mut self, n: u64) {
        let base = self.charset.len() as u128;
        let mut rem = n as u128;
        let mut len = self.min_len;
        loop {
            let size = base.pow(len as u32);
            if rem < size || len == self.max_len {
                break;
            }
            rem -= size;
            len += 1;
        }
        if len == self.max_len && rem >= base.pow(len as u32) {
            self.exhausted = true;
            return;
        }
        // Odometer order: right-most digit cycles fastest → `rem` is the
        // index in little-endian base-|charset|.
        self.len = len;
        self.idx = vec![0; len];
        for pos in (0..len).rev() {
            self.idx[pos] = (rem % base) as usize;
            rem /= base;
        }
        self.exhausted = false;
    }
}

impl Iterator for BruteForce {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.exhausted {
            return None;
        }
        let word: Vec<u8> = self.idx.iter().map(|&d| self.charset[d]).collect();
        // Advance the odometer; carry beyond the left-most digit either
        // grows the word length or exhausts the space.
        let mut pos = self.idx.len();
        loop {
            if pos == 0 {
                if self.len == self.max_len {
                    self.exhausted = true;
                } else {
                    self.len += 1;
                    self.idx = vec![0; self.len];
                }
                break;
            }
            pos -= 1;
            self.idx[pos] += 1;
            if self.idx[pos] < self.charset.len() {
                break;
            }
            self.idx[pos] = 0;
        }
        Some(word)
    }
}

// ---------------------------------------------------------------------------
// Mutation rules (hashcat-subset) — wordlist × rules attack
// ---------------------------------------------------------------------------

/// One hashcat-style single-letter op (supported subset). `$X`/`^X` carry
/// the literal byte; `sXY` carries (from, to).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Noop,
    Lower,
    Upper,
    Capitalize,
    InvertCapitalize,
    Toggle,
    Reverse,
    Duplicate,
    Append(u8),
    Prepend(u8),
    DeleteFirst,
    DeleteLast,
    Replace(u8, u8),
}

/// One rule = a line's ops, applied left to right (`c $1 $9` etc.).
pub type Rule = Vec<Op>;

/// Apply `ops` to `word`, left to right. `None` when the result falls
/// outside the WPA passphrase range 8..=63 — filtered like WordIter, but
/// the flattened index CONSUMES that candidate (resume positions line up
/// with the raw stream).
fn apply_rule(ops: &Rule, word: &[u8]) -> Option<Vec<u8>> {
    let mut w = word.to_vec();
    for op in ops {
        match op {
        Op::Noop => {}
        Op::Lower => w.make_ascii_lowercase(),
        Op::Upper => w.make_ascii_uppercase(),
        Op::Capitalize => {
            w.make_ascii_lowercase();
            if let Some(first) = w.first_mut() {
                first.make_ascii_uppercase();
            }
        }
        Op::InvertCapitalize => {
            w.make_ascii_uppercase();
            if let Some(first) = w.first_mut() {
                first.make_ascii_lowercase();
            }
        }
        Op::Toggle => {
            for b in &mut w {
                if b.is_ascii_lowercase() {
                    *b = b.to_ascii_uppercase();
                } else if b.is_ascii_uppercase() {
                    *b = b.to_ascii_lowercase();
                }
            }
        }
        Op::Reverse => w.reverse(),
        Op::Duplicate => {
            let tail = w.clone();
            w.extend_from_slice(&tail);
        }
        Op::Append(b) => w.push(*b),
        Op::Prepend(b) => w.insert(0, *b),
        Op::DeleteFirst => {
            if !w.is_empty() {
                w.remove(0);
            }
        }
        Op::DeleteLast => {
            w.pop();
        }
        Op::Replace(x, y) => {
            for b in &mut w {
                if b == x {
                    *b = *y;
                }
            }
        }
        }
    }
    (8..=63).contains(&w.len()).then_some(w)
}

/// Parse one rules line into ops. The grammar is byte-oriented: `$`/`^`
/// take the next byte as the literal to append/prepend, `s` takes the two
/// following bytes. Fails with a positioned message on unknown ops or
/// truncated literals.
fn parse_rule_line(line: &[u8], lineno: usize) -> Result<Rule> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    while i < line.len() {
        let c = line[i];
        i += 1;
        let op = match c {
            // Space separates ops in hashcat files ("c $1 $!" etc.) and is
            // itself a do-nothing op there; skip it. Appending a literal
            // space still works ("$ " — the space is $'s literal).
            b' ' => continue,
            b':' => Op::Noop,
            b'l' => Op::Lower,
            b'u' => Op::Upper,
            b'c' => Op::Capitalize,
            b'C' => Op::InvertCapitalize,
            b't' => Op::Toggle,
            b'r' => Op::Reverse,
            b'd' => Op::Duplicate,
            b'[' => Op::DeleteFirst,
            b']' => Op::DeleteLast,
            b'$' | b'^' => {
                let Some(&lit) = line.get(i) else {
                    bail!("rules line {lineno}: `{c}` at column {i} is missing its character");
                };
                i += 1;
                if c == b'$' { Op::Append(lit) } else { Op::Prepend(lit) }
            }
            b's' => {
                let Some(&x) = line.get(i) else {
                    bail!("rules line {lineno}: `s` at column {i} is missing its replacement chars");
                };
                let Some(&y) = line.get(i + 1) else {
                    bail!("rules line {lineno}: `s` at column {i} is missing its replacement chars");
                };
                i += 2;
                Op::Replace(x, y)
            }
            _ => bail!("rules line {lineno}: unsupported op `{}` (column {})", c as char, i - 1),
        };
        ops.push(op);
    }
    Ok(ops)
}

/// Parse a hashcat-subset rules file (the classic best64.rule family):
/// blank lines and lines starting with `#` are skipped, every other line
/// is one rule. The "::"-style noop lines parse to a single [`Op::Noop`]
/// per `:`.
pub fn parse_rules(path: &Path) -> Result<Vec<Rule>> {
    use std::io::BufRead;

    let f = std::fs::File::open(path)
        .with_context(|| format!("opening rules file {}", path.display()))?;
    let mut reader = std::io::BufReader::with_capacity(1 << 16, f);
    let mut rules = Vec::new();
    let mut line = String::new();
    let mut lineno = 0usize;
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .with_context(|| format!("reading rules file {}", path.display()))?;
        if n == 0 {
            break;
        }
        lineno += 1;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        rules.push(parse_rule_line(trimmed.as_bytes(), lineno)?);
    }
    Ok(rules)
}

/// Count of real rules (non-blank, non-comment lines) — the per-word
/// multiplier for the rules attack's flattened space. Consumed by the
/// cracker-page estimator (W4 UI surface).
#[allow(dead_code)]
pub fn rule_count(path: &Path) -> Result<u64> {
    use std::io::BufRead;

    let f = std::fs::File::open(path)
        .with_context(|| format!("opening rules file {}", path.display()))?;
    let mut count = 0u64;
    for line in std::io::BufReader::with_capacity(1 << 16, f).lines() {
        let line = line.with_context(|| format!("reading rules file {}", path.display()))?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            count += 1;
        }
    }
    Ok(count)
}

/// wordlist × rules generator, WORD-MAJOR / rule-minor: rules are applied
/// to word 0 in file order, then to word 1, and so on. The flattened
/// candidate index of `(word_idx, rule_idx)` is `word_idx * rules_len +
/// rule_idx`, so a resume position is a plain `skip_n` over this stream —
/// even though rule outputs outside 8..=63 are filtered (they still
/// consume a flattened index, matching [`apply_rule`]'s contract).
pub struct RuleIter {
    words: Box<dyn Iterator<Item = Vec<u8>> + Send>,
    rules: Rc<Vec<Rule>>,
    cur: Option<Vec<u8>>,
    ri: usize,
}

impl RuleIter {
    pub fn new(words: Box<dyn Iterator<Item = Vec<u8>> + Send>, rules: Rc<Vec<Rule>>) -> Self {
        if rules.is_empty() {
            // Degenerate case: keep the stream empty rather than panic.
            return RuleIter { words: Box::new(std::iter::empty()), rules, cur: None, ri: 0 };
        }
        RuleIter { words, rules, cur: None, ri: 0 }
    }
}

impl Iterator for RuleIter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.cur.is_none() {
                self.cur = Some(self.words.next()?);
                self.ri = 0;
            }
            let cur = self.cur.clone().expect("just filled");
            while self.ri < self.rules.len() {
                let r = &self.rules[self.ri];
                self.ri += 1;
                if let Some(out) = apply_rule(r, &cur) {
                    return Some(out);
                }
                // Filtered: the index slot is consumed (documented above).
            }
            self.cur = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Hybrid: wordlist × append-charset sweep (word + charset^k)
// ---------------------------------------------------------------------------

/// wordlist × append-charset generator: for each word yields
/// `word + charset^k` for k in `min..=max`, rightmost-fastest odometer
/// like [`BruteForce`]. Suffix lengths `min`/`max` are clamped to 1..=4
/// (the bruteforce-ish complement of the wordlist — longer suffixes
/// belong to plain bruteforce). Candidates longer than 63 bytes are
/// skipped AFTER consuming their flattened index (like [`RuleIter`]).
///
/// Flattened index of `(word_idx, inner)` is `word_idx * per_word +
/// inner` with `per_word = Σ_{k=min..=max} |charset|^k`; `inner` walks
/// k-blocks in ascending order with little-endian odometer order inside a
/// block (same convention as [`BruteForce`]). `total = line_count(wordlist)
/// * per_word` is an upper bound (length-skipping only shrinks it).
pub struct HybridIter {
    words: Box<dyn Iterator<Item = Vec<u8>> + Send>,
    charset: Vec<u8>,
    min: usize,
    max: usize,
    /// Current wordlist word (None = load the next one).
    cur_word: Option<Vec<u8>>,
    /// Suffix length currently emitted for `cur_word`.
    k: usize,
    /// Odometer digits for the current suffix length.
    odo: Vec<usize>,
    /// Set by `seek_flat`: the odometer was primed externally and the next
    /// word load must NOT reset it.
    primed: bool,
}

impl HybridIter {
    /// `Err` when the charset is empty or the clamped suffix range is
    /// inverted (`min` > `max` after clamping: `min` 4 with `max` 1 etc.).
    pub fn new(
        words: Box<dyn Iterator<Item = Vec<u8>> + Send>,
        charset: Vec<u8>,
        min: usize,
        max: usize,
    ) -> Result<Self> {
        let (min, max) = Self::clamped_range(min, max)?;
        let mut charset = charset;
        charset.sort_unstable();
        charset.dedup();
        if charset.is_empty() {
            bail!("hybrid: charset is empty");
        }
        Ok(HybridIter {
            words,
            charset,
            min,
            max,
            cur_word: None,
            k: min,
            odo: vec![0; min],
            primed: false,
        })
    }

    /// Flag validation for [`Attack::Hybrid`] (no word stream needed).
    pub fn validate(charset: &[u8], min: usize, max: usize) -> Result<()> {
        let mut cs = charset.to_vec();
        cs.sort_unstable();
        cs.dedup();
        if cs.is_empty() {
            bail!("hybrid: charset is empty");
        }
        Self::clamped_range(min, max).map(|_| ())
    }

    fn clamped_range(min: usize, max: usize) -> Result<(usize, usize)> {
        let lo = min.clamp(1, 4);
        let hi = max.clamp(1, 4);
        if lo > hi {
            bail!("hybrid: suffix length range {min}..={max} is inverted (clamped 1..=4)");
        }
        Ok((lo, hi))
    }

    /// Candidates emitted per wordlist word: Σ_{k=min..=max} |charset|^k
    /// (saturated to u64::MAX).
    pub fn per_word(&self) -> u64 {
        let base = self.charset.len() as u128;
        let s: u128 = (self.min..=self.max).map(|k| base.pow(k as u32)).sum();
        s.min(u64::MAX as u128) as u64
    }

    /// Position the generator at flattened index `n` (resume): skips
    /// `n / per_word` words and primes the suffix odometer to emit the
    /// remainder `n % per_word`. An `n` beyond the space leaves the stream
    /// at its natural end.
    pub fn seek_flat(&mut self, n: u64) {
        let per_word = self.per_word();
        let word_idx = if per_word == 0 { n } else { n / per_word };
        let inner = if per_word == 0 { 0 } else { n % per_word };
        skip_n(&mut self.words, word_idx);
        self.set_inner(inner as u128);
        // The skipped words leave cur_word empty; next() loads the word at
        // word_idx (or the stream ends) — WITHOUT clobbering the primed
        // odometer (one word only).
        self.cur_word = None;
        self.primed = true;
    }

    /// Prime the odometer so the next calls yield suffix-block index
    /// `inner` (ascending k-blocks, little-endian odometer per block).
    fn set_inner(&mut self, mut rem: u128) {
        let base = self.charset.len() as u128;
        let mut k = self.min;
        loop {
            let size = base.pow(k as u32);
            if rem < size || k == self.max {
                break;
            }
            rem -= size;
            k += 1;
        }
        // rem can exceed the last block only when `inner` pointed past the
        // whole per-word space (callers never produce that), but stay
        // defensive: exhaust the stream at the first next().
        let mut odo = vec![0usize; k];
        for pos in (0..k).rev() {
            odo[pos] = (rem % base) as usize;
            rem /= base;
        }
        if rem > 0 {
            // Sentinel: out-of-range digit exhausts at the first next().
            self.k = k;
            self.odo = vec![self.charset.len(); k];
            return;
        }
        self.k = k;
        self.odo = odo;
    }
}

impl Iterator for HybridIter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.cur_word.is_none() {
                self.cur_word = Some(self.words.next()?);
                // seek_flat-primed state survives the first word load;
                // afterwards the odometer restarts at zero per word.
                if !self.primed {
                    self.k = self.min;
                    self.odo = vec![0; self.k];
                }
                self.primed = false;
            }
            let word = self.cur_word.clone().expect("just filled");
            // Out-of-range sentinel from set_inner: exhaust.
            if self.odo.iter().any(|&d| d >= self.charset.len()) {
                self.cur_word = None;
                continue;
            }
            let mut cand = word.clone();
            for d in &self.odo {
                cand.push(self.charset[*d]);
            }
            // Advance the odometer: rightmost fastest; carry grows k until
            // max is exhausted, which moves on to the next word.
            let mut pos = self.odo.len();
            loop {
                if pos == 0 {
                    if self.k == self.max {
                        self.cur_word = None;
                    } else {
                        self.k += 1;
                        self.odo = vec![0; self.k];
                    }
                    break;
                }
                pos -= 1;
                self.odo[pos] += 1;
                if self.odo[pos] < self.charset.len() {
                    break;
                }
                self.odo[pos] = 0;
            }
            // >63-byte candidates are skipped but consumed the index.
            if cand.len() <= 63 {
                return Some(cand);
            }
            // word exhausted check: when the suffix made it not fit at k,
            // larger k will not either — jump straight to the next word.
            if word.len() + self.k + 1 > 63 {
                self.cur_word = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PMK-cache coverage filter
// ---------------------------------------------------------------------------

/// Wraps a candidate stream, dropping candidates already covered by the
/// per-SSID PMK cache consult (they were shown not to match). Skipped
/// candidates do NOT count against `done` — the cache pass replaced the
/// work; resume indices still refer to the RAW stream (worst-case).
pub struct CacheSkipIter<I: Iterator<Item = Vec<u8>>> {
    inner: I,
    covered: HashSet<Box<[u8]>>,
}

impl<I: Iterator<Item = Vec<u8>>> CacheSkipIter<I> {
    pub fn new(inner: I, covered: HashSet<Box<[u8]>>) -> Self {
        CacheSkipIter { inner, covered }
    }
}

impl<I: Iterator<Item = Vec<u8>>> Iterator for CacheSkipIter<I> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        for cand in self.inner.by_ref() {
            if !self.covered.contains(cand.as_slice()) {
                return Some(cand);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

fn send(tx: &Sender<Event>, ev: Event) {
    let _ = tx.send(ev);
}

fn log(tx: &Sender<Event>, line: impl Into<String>) {
    send(tx, Event::Log(line.into()));
}

fn log_err(tx: &Sender<Event>, line: impl Into<String>) {
    send(tx, Event::Error(line.into()));
}

/// GPU (or CPU-fallback) PBKDF2 crack over a word stream — the selection
/// logic the cracker has always used. `total` is the worst-case candidate
/// count (worst-case ETA = (total - done) / hps) when the source is
/// countable. `force_cpu` skips the GPU entirely (CLI `--cpu`); it also
/// disables the PMK-cache sink so a forced-CPU client run stays
/// side-effect-free. Otherwise a PURE-CPU run (no adapter, or a key_ver
/// the shader cannot express) populates the per-SSID PMK cache while it
/// cracks — every candidate's PBKDF2 result lands in
/// `store::cache_file(essid)` in rainbow format.
fn word_crack(
    target_desc: &str,
    target: &CrackTarget,
    words: &mut dyn Iterator<Item = Vec<u8>>,
    total: Option<u64>,
    done_offset: u64,
    tx: &Sender<Event>,
    stop: &Arc<AtomicBool>,
    force_cpu: bool,
) -> Option<String> {
    if let Some(t) = total {
        log(tx, format!("cracker: worst case: {t} candidates"));
    }
    let mut progress = {
        let tx = tx.clone();
        move |done: u64, hps: f64| {
            send(&tx, Event::CrackProgress { done: done_offset + done, hps, total })
        }
    };
    // SHA1-family targets (handshake key_ver 1|2, PMKID) crack fully
    // on-device (init + chain + MIC epilogue); key_ver 3 / overlong
    // ESSIDs stay on the CPU cracker even when a GPU exists.
    let adapter = if !force_cpu && gpu::gpu_verifiable(target) { GpuCracker::try_new() } else { None };
    match adapter {
        Some(g) => {
            log(
                tx,
                format!("cracker: GPU backend: {} — cracking {target_desc}", g.device_name()),
            );
            // GPU runs never populate the cache: the hit-slot readback
            // pipeline has no PMK readback plumbed through it.
            g.crack(target, words, &mut progress, stop)
        }
        None => {
            log(
                tx,
                if force_cpu {
                    format!("cracker: CPU backend (forced) — cracking {target_desc}")
                } else {
                    format!("cracker: CPU backend (no adapter or non-SHA1 target) — cracking {target_desc}")
                },
            );
            let mut sink = if force_cpu {
                None
            } else {
                let path = store::cache_file(target.essid());
                match rainbow::append_open(&path, target.essid()) {
                    Ok(w) => Some(gpu::CpuPmkSink::new(w, {
                        let tx = tx.clone();
                        Box::new(move |line: String| log(&tx, line))
                    })),
                    Err(e) => {
                        log(
                            tx,
                            format!("pmk cache: cannot open cache file for writing ({e:#}) — continuing without"),
                        );
                        None
                    }
                }
            };
            let found = gpu::cpu_crack(target, words, &mut progress, stop, sink.as_mut());
            if let Some(s) = sink {
                match s.finish() {
                    Ok(n) => log(tx, format!("pmk cache: {n} PMKs cached → {}", store::cache_file(target.essid()).display())),
                    Err(e) => log(tx, format!("pmk cache: flush failed ({e:#})")),
                }
            }
            found
        }
    }
}

/// Rainbow run: precomputed PMKs, one PTK derivation + MIC compare per
/// entry (no PBKDF2). Progress ticks are time-based (~4/s) so a fast disk
/// is not reporting-bound.
pub fn rainbow_crack(
    target: &CrackTarget,
    entries: &mut dyn Iterator<Item = ([u8; 32], Vec<u8>)>,
    progress: &mut dyn FnMut(u64, f64),
    stop: &Arc<AtomicBool>,
) -> Option<String> {
    let prepared = gpu::prepare_target(target);
    let mut done = 0u64;
    let started = Instant::now();
    let mut last_tick = started;
    for (pmk, pass) in entries {
        done += 1;
        if gpu::prepared_matches(&prepared, &pmk) {
            progress(done, done as f64 / started.elapsed().as_secs_f64().max(1e-6));
            return String::from_utf8(pass).ok();
        }
        if last_tick.elapsed() > Duration::from_millis(250) {
            last_tick = Instant::now();
            progress(done, done as f64 / started.elapsed().as_secs_f64().max(1e-6));
        }
        if done % 4096 == 0 && stop.load(Ordering::Relaxed) {
            return None;
        }
    }
    // Exhaustion: a table smaller than one tick interval would otherwise
    // end with zero progress ever reported (the word path ticks per
    // batch — match it).
    progress(done, done as f64 / started.elapsed().as_secs_f64().max(1e-6));
    None
}

/// Drop the first `n` items of a candidate stream (resume). The stream
/// simply runs out early when fewer than `n` remain — the caller's crack
/// loop then reports "exhausted" on the empty remainder.
fn skip_n<T>(it: &mut dyn Iterator<Item = T>, mut n: u64) {
    while n > 0 && it.next().is_some() {
        n -= 1;
    }
}

/// Result of consulting the per-SSID PMK cache before a wordlist-family run.
enum CacheConsult {
    /// Cache contained the PSK — report as a normal find, skip the main run.
    Hit(String),
    /// Readable cache, no match: the covered passphrases to skip in the
    /// main iterator.
    Miss(HashSet<Box<[u8]>>),
    /// No cache, or unreadable — run everything.
    Skip,
}

/// Per-SSID PMK cache consult (`~/wifilab/cache/<ssid-hex>.pmk`, rainbow
/// text format): if the file exists and is readable, run a quick
/// PBKDF2-free pass ([`rainbow_crack`]) over its entries BEFORE the main
/// attack. On a miss the caller wraps the main iterator in
/// [`CacheSkipIter`] so cached-and-ruled-out passwords are not recomputed.
/// Unreadable caches (open/parse/header-SSID mismatch) produce exactly
/// one `Log` and fall through to a full run.
fn consult_cache(
    target: &CrackTarget,
    attack_desc: &str,
    tx: &Sender<Event>,
    stop: &Arc<AtomicBool>,
) -> CacheConsult {
    let path = store::cache_file(target.essid());
    if !path.is_file() {
        return CacheConsult::Skip;
    }
    let mut entries = match rainbow::open(&path) {
        Ok((ssid, entries)) => match rainbow::check_ssid(ssid.as_deref(), target.essid()) {
            Ok(()) => entries,
            Err(e) => {
                log(tx, format!("pmk cache: unreadable ({e:#}), proceeding without"));
                return CacheConsult::Skip;
            }
        },
        Err(e) => {
            log(tx, format!("pmk cache: unreadable ({e:#}), proceeding without"));
            return CacheConsult::Skip;
        }
    };
    let total = wordlist::line_count(&path).ok().map(|n| n.max(1));
    let mut covered: HashSet<Box<[u8]>> = HashSet::new();
    // Tee the password out of each entry while rainbow_crack consumes.
    let mut teed = std::iter::from_fn(|| {
        entries.next().map(|(pmk, pass)| {
            covered.insert(pass.clone().into_boxed_slice());
            (pmk, pass)
        })
    });
    let mut progress = {
        let tx = tx.clone();
        move |done: u64, hps: f64| {
            send(&tx, Event::CrackProgress { done, hps, total });
        }
    };
    log(tx, "pmk cache: file exists — checking cached PMKs first");
    if let Some(pass) = rainbow_crack(target, &mut teed, &mut progress, stop) {
        return CacheConsult::Hit(pass);
    }
    if stop.load(Ordering::Relaxed) {
        // Stopped mid-consult: treat as a miss; the main run's stop checks
        // produce the canonical "stopped" terminator.
        return CacheConsult::Miss(covered);
    }
    log(tx, format!("pmk cache: {} entries, no hit — continuing {attack_desc}", covered.len()));
    CacheConsult::Miss(covered)
}

/// Start a crack run on a background thread. Always returns the stop flag;
/// spawn failure is reported as events instead of a thread. `resume_from`
/// skips that many leading candidates (saved position of a previous run —
/// a FLATTENED index for rules/hybrid, see [`RuleIter`]/[`HybridIter`]);
/// progress events still count from zero of the FULL space. `force_cpu`
/// pins the CPU backend (headless CLI `--cpu`) and disables PMK-cache
/// writes. Wordlist-family attacks first consult the per-SSID PMK cache
/// (`store::cache_file`): hit → the normal found-terminator without a
/// main run; miss → cached passwords are skipped via [`CacheSkipIter`].
pub fn spawn_crack(
    target_desc: String,
    target: CrackTarget,
    attack: Attack,
    resume_from: u64,
    tx: Sender<Event>,
    force_cpu: bool,
) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let err_tx = tx.clone();
    let result = std::thread::Builder::new()
        .name("wifilab-crack".into())
        .spawn(move || {
            if resume_from > 0 {
                log(&tx, format!("cracker: resuming at candidate {resume_from}"));
            }
            // Per-SSID PMK cache consult (wordlist-family only).
            let wordlist_family = matches!(
                attack,
                Attack::Wordlist(_)
                    | Attack::Rules { .. }
                    | Attack::Hybrid { .. }
                    | Attack::Bruteforce { .. }
            );
            let mut covered: Option<HashSet<Box<[u8]>>> = None;
            if wordlist_family {
                match consult_cache(&target, &attack.describe(), &tx, &stop2) {
                    CacheConsult::Hit(password) => {
                        log(&tx, format!("cracker: PASSWORD found: {password}"));
                        send(&tx, Event::CrackFound { password });
                        send(&tx, Event::CrackStopped { found: true });
                        return;
                    }
                    CacheConsult::Miss(c) => covered = Some(c),
                    CacheConsult::Skip => {}
                }
            }
            // Wrap a candidate stream with the coverage filter from the
            // cache consult (when one happened).
            fn with_cache<I: Iterator<Item = Vec<u8>> + 'static>(
                it: I,
                covered: &mut Option<HashSet<Box<[u8]>>>,
            ) -> Box<dyn Iterator<Item = Vec<u8>>> {
                match covered.take() {
                    Some(c) => Box::new(CacheSkipIter::new(it, c)),
                    None => Box::new(it),
                }
            }
            let found = match &attack {
                Attack::Wordlist(path) => match wordlist::open(path) {
                    Ok(mut words) => {
                        // Line count is an upper bound (length-filtering
                        // only shrinks the space — exactly the "worst
                        // case" the ETA promises).
                        let total = wordlist::line_count(path).ok();
                        skip_n(&mut words, resume_from);
                        let mut words = with_cache(words, &mut covered);
                        word_crack(&target_desc, &target, &mut words, total, resume_from, &tx, &stop2, force_cpu)
                    }
                    Err(e) => {
                        log_err(&tx, format!("cracker: {e:#}"));
                        None
                    }
                },
                Attack::Rules { wordlist: wl_path, rules: rules_path } => {
                    match (wordlist::open(wl_path), parse_rules(rules_path)) {
                        (Ok(words), Ok(rules)) => {
                            let n_rules = rules.len() as u128;
                            let lines = wordlist::line_count(wl_path).ok();
                            // Worst case: every word × every rule.
                            let total =
                                lines.map(|l| (l as u128).saturating_mul(n_rules).min(u64::MAX as u128) as u64);
                            let mut it = RuleIter::new(words, Rc::new(rules));
                            // Flattened index resume: a plain skip.
                            skip_n(&mut it, resume_from);
                            let mut it = with_cache(it, &mut covered);
                            word_crack(&target_desc, &target, &mut it, total, resume_from, &tx, &stop2, force_cpu)
                        }
                        (Err(e), _) => {
                            log_err(&tx, format!("cracker: {e:#}"));
                            None
                        }
                        (_, Err(e)) => {
                            log_err(&tx, format!("cracker: {e:#}"));
                            None
                        }
                    }
                }
                Attack::Hybrid { wordlist: wl_path, charset, min, max } => {
                    match wordlist::open(wl_path) {
                        Ok(words) => {
                            let mut it = HybridIter::new(words, charset.clone(), *min, *max)
                                .expect("validated");
                            let lines = wordlist::line_count(wl_path).ok();
                            let total = lines.map(|l| {
                                (l as u128).saturating_mul(it.per_word() as u128).min(u64::MAX as u128)
                                    as u64
                            });
                            // Exact flattened-index resume.
                            it.seek_flat(resume_from);
                            let mut it = with_cache(it, &mut covered);
                            word_crack(&target_desc, &target, &mut it, total, resume_from, &tx, &stop2, force_cpu)
                        }
                        Err(e) => {
                            log_err(&tx, format!("cracker: {e:#}"));
                            None
                        }
                    }
                }
                Attack::Bruteforce { charset, min, max, freq_order } => {
                    // validate() runs before spawn; new() cannot fail here.
                    let mut brute =
                        BruteForce::new(charset.clone(), *min, *max, *freq_order).expect("validated");
                    let total = Some(brute.space().min(u64::MAX as u128) as u64);
                    // Exact seek (no skipping): O(1) odometer math.
                    brute.seek(resume_from);
                    let mut brute = with_cache(brute, &mut covered);
                    word_crack(&target_desc, &target, &mut brute, total, resume_from, &tx, &stop2, force_cpu)
                }
                Attack::Rainbow(path) => match rainbow::open(path) {
                    Ok((ssid, mut entries)) => {
                        if let Err(e) = rainbow::check_ssid(ssid.as_deref(), target.essid()) {
                            log_err(&tx, format!("cracker: {e:#}"));
                            None
                        } else {
                            let total = wordlist::line_count(path).ok();
                            skip_n(&mut entries, resume_from);
                            let mut progress = {
                                let tx = tx.clone();
                                move |done: u64, hps: f64| {
                                    send(&tx, Event::CrackProgress { done: resume_from + done, hps, total })
                                }
                            };
                            log(
                                &tx,
                                format!("cracker: rainbow run (precomputed PMKs) — {target_desc}"),
                            );
                            rainbow_crack(&target, &mut entries, &mut progress, &stop2)
                        }
                    }
                    Err(e) => {
                        log_err(&tx, format!("cracker: {e:#}"));
                        None
                    }
                },
            };
            match found {
                Some(password) => {
                    log(&tx, format!("cracker: PASSWORD found: {password}"));
                    send(&tx, Event::CrackFound { password });
                    send(&tx, Event::CrackStopped { found: true });
                }
                None => {
                    if stop2.load(Ordering::Relaxed) {
                        log(&tx, "cracker: stopped");
                    } else {
                        log(&tx, "cracker: candidates exhausted, password not found");
                    }
                    send(&tx, Event::CrackStopped { found: false });
                }
            }
        });
    if let Err(e) = result {
        send(&err_tx, Event::Error(format!("cracker: spawn failed: {e}")));
        send(&err_tx, Event::CrackStopped { found: false });
    }
    stop
}

/// Build a rainbow PMK table for `ssid` from a wordlist (PBKDF2 once —
/// GPU when available), so later runs against that SSID are PBKDF2-free.
/// Always ends with exactly one `RainbowBuilt` (entries written so far),
/// preceded by `Error` events on failure.
pub fn spawn_rainbow_build(
    ssid: String,
    wordlist: PathBuf,
    out: PathBuf,
    tx: Sender<Event>,
) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let err_tx = tx.clone();
    let out2 = out.clone();
    let result = std::thread::Builder::new()
        .name("wifilab-rainbow-build".into())
        .spawn(move || {
            let entries = build_table(&ssid, &wordlist, &out2, &tx, &stop2);
            send(
                &tx,
                Event::RainbowBuilt {
                    path: out2.display().to_string(),
                    entries,
                },
            );
        });
    if let Err(e) = result {
        send(&err_tx, Event::Error(format!("rainbow: spawn failed: {e}")));
        send(
            &err_tx,
            Event::RainbowBuilt {
                path: out.display().to_string(),
                entries: 0,
            },
        );
    }
    stop
}

/// The build loop: wordlist batches → PMKs (GPU batch or per-word CPU) →
/// table file. Returns entries actually written.
fn build_table(
    ssid: &str,
    wordlist_path: &PathBuf,
    out: &PathBuf,
    tx: &Sender<Event>,
    stop: &Arc<AtomicBool>,
) -> u64 {
    let mut words = match wordlist::open(wordlist_path) {
        Ok(w) => w,
        Err(e) => {
            log_err(tx, format!("rainbow: {e:#}"));
            return 0;
        }
    };
    let mut table = match rainbow::create(out, ssid) {
        Ok(t) => t,
        Err(e) => {
            log_err(tx, format!("rainbow: {e:#}"));
            return 0;
        }
    };
    let gpu = GpuCracker::try_new();
    log(
        tx,
        match &gpu {
            Some(g) => format!("rainbow: building via GPU ({}) → {}", g.device_name(), out.display()),
            None => format!("rainbow: building via CPU → {}", out.display()),
        },
    );

    const BATCH: usize = 4096;
    let salt = ssid.as_bytes();
    let total = wordlist::line_count(wordlist_path).ok();
    let mut written = 0u64;
    let started = Instant::now();
    let mut last_tick = started;
    'outer: loop {
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(BATCH);
        while batch.len() < BATCH {
            match words.next() {
                Some(w) => batch.push(w),
                None => break,
            }
        }
        if batch.is_empty() {
            break;
        }
        let pmks = match &gpu {
            Some(g) => match g.pmk_batch_gpu(&batch, salt) {
                // Device hiccup even after the internal halving: give up,
                // the partial table stays usable.
                None => {
                    log_err(tx, "rainbow: GPU batch failed — table left partial");
                    break 'outer;
                }
                Some(p) => p,
            },
            None => batch.iter().map(|w| crypto::pmk(w, salt)).collect(),
        };
        for (pmk, w) in pmks.iter().zip(batch.iter()) {
            if let Err(e) = table.push(pmk, w) {
                log_err(tx, format!("rainbow: write failed: {e:#}"));
                break 'outer;
            }
            written += 1;
        }
        if last_tick.elapsed() > Duration::from_millis(250) {
            last_tick = Instant::now();
            let secs = started.elapsed().as_secs_f64().max(1e-6);
            send(tx, Event::RainbowProgress { done: written, hps: written as f64 / secs, total });
        }
        if stop.load(Ordering::Relaxed) {
            log(tx, "rainbow: build stopped — partial table kept");
            break;
        }
    }
    match table.finish() {
        Ok(n) => n,
        Err(e) => {
            log_err(tx, format!("rainbow: flush failed: {e:#}"));
            written
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark — measured H/s for the crack-time estimator
// ---------------------------------------------------------------------------

/// CPU half of the benchmark: time `crypto::pmk` over candidate-sized
/// batches and report hashes/sec. Runs at least one batch; honors `stop`
/// between batches.
fn bench_cpu(secs: f64, stop: Option<&AtomicBool>) -> f64 {
    const BATCH: u64 = 512;
    let word = b"benchmark1";
    let salt = b"wifilab-bench";
    let started = Instant::now();
    let mut done = 0u64;
    loop {
        for _ in 0..BATCH {
            std::hint::black_box(crypto::pmk(std::hint::black_box(word), salt));
        }
        done += BATCH;
        let elapsed = started.elapsed().as_secs_f64();
        if elapsed >= secs {
            return done as f64 / elapsed.max(1e-6);
        }
        if let Some(s) = stop {
            if s.load(Ordering::Relaxed) {
                return done as f64 / elapsed.max(1e-6);
            }
        }
    }
}

/// GPU half: batches of 4096 fixed words through the PMK kernel for
/// `secs`; `None` when no adapter exists (or the first dispatch fails —
/// the CPU number is still meaningful then).
fn bench_gpu(secs: f64, stop: Option<&AtomicBool>) -> Option<f64> {
    let g = GpuCracker::try_new()?;
    const BATCH: usize = 4096;
    let batch = vec![b"benchmark1".to_vec(); BATCH];
    let salt = b"wifilab-bench";
    let started = Instant::now();
    let mut done = 0u64;
    loop {
        done += g.pmk_batch_gpu(&batch, salt)?.len() as u64;
        let elapsed = started.elapsed().as_secs_f64();
        if elapsed >= secs {
            return Some(done as f64 / elapsed.max(1e-6));
        }
        if let Some(s) = stop {
            if s.load(Ordering::Relaxed) {
                return Some(done as f64 / elapsed.max(1e-6));
            }
        }
    }
}

/// Measure crack throughput on this machine for `seconds` per backend:
/// returns `(gpu_hps, cpu_hps)` where the GPU half is `None` without an
/// adapter. Honoring `stop` between batches; `None` stop = run to time.
/// Synchronous — wrap it in [`spawn_benchmark`] for UI use.
#[allow(dead_code)]
pub fn benchmark(seconds: u32) -> (Option<f64>, f64) {
    let secs = seconds.max(1) as f64;
    (bench_gpu(secs, None), bench_cpu(secs, None))
}

/// Benchmark on a background thread ("wifilab-benchmark"); terminates
/// with exactly one `Event::BenchmarkDone { gpu_hps, cpu_hps }` (on spawn
/// failure: an `Error` plus a zeroed `BenchmarkDone`). Honors the stop
/// flag between batches. The UI guards against running it alongside a
/// crack or rainbow build.
#[allow(dead_code)]
pub fn spawn_benchmark(seconds: u32, tx: Sender<Event>) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let err_tx = tx.clone();
    let result = std::thread::Builder::new()
        .name("wifilab-benchmark".into())
        .spawn(move || {
            log(&tx, format!("benchmark: measuring crack speed ({seconds}s per backend)"));
            let secs = seconds.max(1) as f64;
            let gpu_hps = bench_gpu(secs, Some(&stop2));
            let cpu_hps = bench_cpu(secs, Some(&stop2));
            send(&tx, Event::BenchmarkDone { gpu_hps, cpu_hps });
        });
    if let Err(e) = result {
        send(&err_tx, Event::Error(format!("benchmark: spawn failed: {e}")));
        send(&err_tx, Event::BenchmarkDone { gpu_hps: None, cpu_hps: 0.0 });
    }
    stop
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{HandshakeCapture, MacAddr};

    fn synthetic_target(ssid: &str, pass: &[u8]) -> CrackTarget {
        let ap: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let sta: MacAddr = "11:22:33:44:55:66".parse().unwrap();
        let anonce = [0x5a; 32];
        let snonce = [0xc3; 32];
        let key = crypto::pmk(pass, ssid.as_bytes());
        let dk = crypto::ptk(&key, &ap, &sta, &anonce, &snonce);
        // Minimal M2 frame (see gpu::tests::build_eapol_m2 — same layout).
        let mut f = Vec::with_capacity(99);
        f.push(0x02);
        f.push(0x03);
        f.extend_from_slice(&95u16.to_be_bytes());
        f.push(0x02);
        let info: u16 = 0x0100 | 0x0080 | 2;
        f.extend_from_slice(&info.to_be_bytes());
        f.extend_from_slice(&16u16.to_be_bytes());
        f.extend_from_slice(&1u64.to_be_bytes());
        f.extend_from_slice(&snonce);
        f.extend_from_slice(&[0u8; 16]);
        f.extend_from_slice(&[0u8; 8]);
        f.extend_from_slice(&[0u8; 8]);
        f.extend_from_slice(&[0u8; 16]);
        f.extend_from_slice(&0u16.to_be_bytes());
        let m = crypto::mic(&dk, &f, 2);
        CrackTarget::Handshake(HandshakeCapture::new(
            ap,
            sta,
            ssid.to_string(),
            anonce,
            snonce,
            m,
            f,
            2,
        ))
    }

    #[test]
    fn bruteforce_order_and_exhaustion() {
        let bf = BruteForce::new(b"ab".to_vec(), 8, 8, false).unwrap();
        let got: Vec<Vec<u8>> = bf.collect();
        assert_eq!(got.len(), 256);
        assert_eq!(got[0], b"aaaaaaaa");
        assert_eq!(got[1], b"aaaaaaab");
        assert_eq!(got[2], b"aaaaaaba");
        assert_eq!(got[255], b"bbbbbbbb");
    }

    #[test]
    fn bruteforce_length_growth_and_clamp() {
        // Length grows only after the shorter space is exhausted; range is
        // clamped into 8..=63.
        let mut bf = BruteForce::new(b"z".to_vec(), 1, 100, false).unwrap();
        assert_eq!(bf.next().unwrap(), b"zzzzzzzz");
        assert_eq!(bf.next().unwrap(), b"zzzzzzzzz");
        let mut bf = BruteForce::new(b"z".to_vec(), 1, 9, false).unwrap();
        assert_eq!(bf.next().unwrap(), b"zzzzzzzz");
        assert_eq!(bf.next().unwrap(), b"zzzzzzzzz");
        assert_eq!(bf.next(), None);
    }

    #[test]
    fn bruteforce_rejects_bad_input() {
        assert!(BruteForce::new(Vec::new(), 8, 12, false).is_err());
        assert!(BruteForce::new(b"a".to_vec(), 64, 70, false).is_err());
        assert!(BruteForce::new(b"a".to_vec(), 12, 8, false).is_err());
    }

    #[test]
    fn bruteforce_seek_lands_exactly() {
        // seek(j) must equal collecting j items — across a length boundary.
        let reference: Vec<Vec<u8>> = BruteForce::new(b"abcde".to_vec(), 8, 9, false).unwrap()
            .take(5usize.pow(8) + 40)
            .collect();
        for j in [0u64, 1, 17, 5u64.pow(8) - 1, 5u64.pow(8), 5u64.pow(8) + 39] {
            let mut bf = BruteForce::new(b"abcde".to_vec(), 8, 9, false).unwrap();
            bf.seek(j);
            let got: Vec<Vec<u8>> = bf.by_ref().take(3).collect();
            let want = &reference[j as usize..(j as usize + 3).min(reference.len())];
            assert_eq!(&got[..want.len()], want, "j={j}");
        }
        // Beyond the space: exhausted.
        let mut bf = BruteForce::new(b"ab".to_vec(), 8, 8, false).unwrap();
        bf.seek(256);
        assert_eq!(bf.next(), None);
    }

    #[test]
    fn bruteforce_space_matches_stream_count() {
        let bf = BruteForce::new(b"abcd".to_vec(), 8, 9, false).unwrap();
        assert_eq!(bf.space(), 4u128.pow(8) + 4u128.pow(9));
        assert_eq!(bf.count() as u128, 4u128.pow(8) + 4u128.pow(9));
    }

    #[test]
    fn rainbow_crack_finds_pass() {
        let pass = b"sup3r-secret";
        let target = synthetic_target("parafin", pass);
        let entries: Vec<([u8; 32], Vec<u8>)> = vec![
            (crypto::pmk(b"nope-nope", b"parafin"), b"nope-nope".to_vec()),
            (crypto::pmk(pass, b"parafin"), pass.to_vec()),
        ];
        let mut it = entries.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let found = rainbow_crack(&target, &mut it, &mut |_, _| {}, &stop);
        assert_eq!(found.as_deref(), Some("sup3r-secret"));
    }

    #[test]
    fn build_then_crack_end_to_end() {
        // The exact files the worker threads touch: wordlist in, table out,
        // crack via the table — no GPU required.
        let dir = std::env::temp_dir();
        let wl = dir.join(format!("wifilab-attack-wl-{}", std::process::id()));
        let tbl = dir.join(format!("wifilab-attack-tbl-{}", std::process::id()));
        std::fs::write(&wl, "nope-nope\nsup3r-secret\nalsonope!\n").unwrap();

        let (etx, erx) = crossbeam_channel::unbounded();
        let stop = Arc::new(AtomicBool::new(false));
        let written = build_table("parafin", &wl, &tbl, &etx, &stop);
        assert_eq!(written, 3);
        let built: Vec<Event> = erx.try_iter().collect();
        assert!(!built.iter().any(|e| matches!(e, Event::Error(_))));

        let target = synthetic_target("parafin", b"sup3r-secret");
        let (ssid, mut entries) = rainbow::open(&tbl).unwrap();
        rainbow::check_ssid(ssid.as_deref(), target.essid()).unwrap();
        let found = rainbow_crack(&target, &mut entries, &mut |_, _| {}, &stop);
        assert_eq!(found.as_deref(), Some("sup3r-secret"));

        // Wrong-ssid table must be refused, not silently exhausted.
        let target2 = synthetic_target("othernet", b"sup3r-secret");
        assert!(rainbow::check_ssid(ssid.as_deref(), target2.essid()).is_err());

        let _ = std::fs::remove_file(&wl);
        let _ = std::fs::remove_file(&tbl);
    }

    #[test]
    fn spawn_crack_emits_progress_and_terminator() {
        // The full worker contract over the channel: starting a run MUST
        // surface progress and exactly one terminator (the historical bug
        // was a run that looked alive at 0 H/s forever). CPU fallback is
        // fine — the GPU path shares the same word_crack wrapper.
        let dir = std::env::temp_dir();
        let wl = dir.join(format!("wifilab-spawn-wl-{}", std::process::id()));
        std::fs::write(&wl, "wrong-pass1\nsup3r-secret\nwrong-pass2\n").unwrap();
        let target = synthetic_target("parafin", b"sup3r-secret");
        let (etx, erx) = crossbeam_channel::unbounded();
        // force_cpu: deterministic CPU run AND no PMK-cache writes into
        // the real ~/wifilab/cache from a test.
        let _stop = spawn_crack(
            target.describe(),
            target,
            Attack::Wordlist(wl.clone()),
            0,
            etx,
            true,
        );
        let mut found = None;
        let mut stopped = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !(stopped) && std::time::Instant::now() < deadline {
            match erx.recv_timeout(Duration::from_secs(5)) {
                Ok(Event::CrackFound { password }) => found = Some(password),
                Ok(Event::CrackStopped { found: true }) => stopped = true,
                Ok(Event::CrackStopped { found: false }) => {
                    panic!("run ended without finding the planted pass")
                }
                Ok(Event::Error(line)) => panic!("worker error: {line}"),
                Ok(_) => {} // Log/CrackProgress
                Err(_) => panic!("channel silent — no events, no terminator"),
            }
        }
        assert!(stopped, "no terminator within deadline");
        assert_eq!(found.as_deref(), Some("sup3r-secret"));
        let _ = std::fs::remove_file(&wl);
    }

    #[test]
    #[ignore = "smoke: user's real stored capture + GPU; run on demand"]
    fn smoke_real_stored_capture() {
        let caps = crate::store::load_captures().expect(" ~/wifilab/captures.jsonl");
        let target = caps
            .iter()
            .find_map(|c| match c {
                crate::store::StoredCapture::Handshake(h) => {
                    Some(CrackTarget::Handshake(h.clone()))
                }
                _ => None,
            })
            .expect("a stored handshake");
        let ssid = target.essid().to_string();
        eprintln!("smoke target: {}", target.describe());

        let dir = std::env::temp_dir();
        let wl = dir.join("wifilab-smoke-wl.txt");
        std::fs::write(&wl, "password123\nletmein123\nqwertyuiop1\n").unwrap();
        let tbl = dir.join("wifilab-smoke.pmk");

        let drain = |erx: &crossbeam_channel::Receiver<Event>, what: &str| {
            let mut saw_progress = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(180);
            loop {
                assert!(std::time::Instant::now() < deadline, "{what}: no terminator");
                match erx.recv_timeout(Duration::from_secs(10)) {
                    Ok(Event::CrackProgress { done, hps, .. } | Event::RainbowProgress { done, hps, .. }) => {
                        if done > 0 {
                            saw_progress = true;
                            assert!(hps > 0.0, "{what}: progress with 0 H/s");
                        }
                    }
                    Ok(Event::CrackStopped { found }) => {
                        assert!(!found, "{what}: unexpected password match");
                        break;
                    }
                    Ok(Event::RainbowBuilt { entries, .. }) => {
                        assert!(entries > 0, "{what}: empty table");
                        break;
                    }
                    Ok(Event::Error(l)) => panic!("{what}: {l}"),
                    Ok(_) => {}
                    Err(_) => panic!("{what}: channel silence"),
                }
            }
            assert!(saw_progress || what.contains("build"), "{what}: zero progress events");
        };

        // 1. wordlist run (GPU): the exact stuck path from the bug report.
        let (tx, rx) = crossbeam_channel::unbounded();
        let _s1 = spawn_crack(target.describe(), target.clone(), Attack::Wordlist(wl.clone()), 0, tx, false);
        drain(&rx, "wordlist run");

        // 2. rainbow build then run (GPU for the build).
        let (tx, rx) = crossbeam_channel::unbounded();
        let _s2 = spawn_rainbow_build(ssid, wl.clone(), tbl.clone(), tx);
        drain(&rx, "rainbow build");
        let (tx, rx) = crossbeam_channel::unbounded();
        let _s3 = spawn_crack(target.describe(), target, Attack::Rainbow(tbl.clone()), 0, tx, false);
        drain(&rx, "rainbow run");

        let _ = std::fs::remove_file(&wl);
        let _ = std::fs::remove_file(&tbl);
    }

    #[test]
    fn resume_from_skips_checked_candidates() {
        // wordlist positions: 0 wrong, 1 wrong, 2 TARGET, 3 wrong.
        let dir = std::env::temp_dir();
        let wl = dir.join(format!("wifilab-resume-wl-{}", std::process::id()));
        std::fs::write(&wl, "wrong-pass1\nwrong-pass2\nsup3r-secret\nwrong-pass3\n").unwrap();
        let target = synthetic_target("parafin", b"sup3r-secret");

        let run = |resume_from: u64| -> (Option<String>, bool) {
            let (etx, erx) = crossbeam_channel::unbounded();
            // force_cpu: keeps the run CPU-deterministic and the real
            // per-SSID PMK cache untouched.
            let _s = spawn_crack(
                target.describe(),
                target.clone(),
                Attack::Wordlist(wl.clone()),
                resume_from,
                etx,
                true,
            );
            let mut pass = None;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                assert!(std::time::Instant::now() < deadline, "no terminator");
                match erx.recv_timeout(Duration::from_secs(5)) {
                    Ok(Event::CrackFound { password }) => pass = Some(password),
                    Ok(Event::CrackStopped { found }) => return (pass, found),
                    Ok(Event::Error(l)) => panic!("worker error: {l}"),
                    Ok(_) => {}
                    Err(_) => panic!("channel silent"),
                }
            }
        };

        // Resume BEFORE the target's position: found.
        assert_eq!(run(2), (Some("sup3r-secret".to_string()), true));
        // Resume past it: exhausted without a match.
        assert_eq!(run(3), (None, false));
        let _ = std::fs::remove_file(&wl);
    }

    #[test]
    fn validate_catches_missing_files() {
        assert!(
            Attack::Wordlist(PathBuf::from("/definitely/not/here.lst"))
                .validate()
                .is_err()
        );
        assert!(
            Attack::Rainbow(PathBuf::from("/definitely/not/here.pmk"))
                .validate()
                .is_err()
        );
        assert!(
            Attack::Bruteforce { charset: b"01".to_vec(), min: 8, max: 10, freq_order: false }
                .validate()
                .is_ok()
        );
        assert!(
            Attack::Rules {
                wordlist: PathBuf::from("/definitely/not/here.lst"),
                rules: PathBuf::from("/definitely/not/here.rule"),
            }
            .validate()
            .is_err()
        );
        assert!(
            Attack::Hybrid {
                wordlist: PathBuf::from("/definitely/not/here.lst"),
                charset: b"01".to_vec(),
                min: 1,
                max: 2,
            }
            .validate()
            .is_err()
        );
        // Inverted (clamped) hybrid suffix range is refused.
        assert!(HybridIter::validate(b"01", 4, 1).is_err());
        assert!(HybridIter::validate(&[], 1, 2).is_err());
    }

    #[test]
    fn rule_ops_golden_table() {
        // One row per op, plus a compound multi-op line ("c $1 $9"-style).
        let cases: &[(&str, &[u8], &[u8])] = &[
            (":", b"password1", b"password1"),
            ("l", b"PassWord1", b"password1"),
            ("u", b"PassWord1", b"PASSWORD1"),
            ("c", b"pASSWORD1", b"Password1"),
            ("C", b"Password1", b"pASSWORD1"),
            ("t", b"PassWord1", b"pASSwORD1"),
            ("r", b"password", b"drowssap"),
            ("d", b"password", b"passwordpassword"),
            ("$1", b"password", b"password1"),
            ("^1", b"password", b"1password"),
            ("[", b"password1", b"assword1"),
            ("]", b"password1", b"password"),
            ("so0", b"password05", b"passw0rd05"),
            // Compound: capitalize, append "1", append "!" — the classic
            // "Password1!" family from an 8-char base word.
            ("c $1 $!", b"password", b"Password1!"),
        ];
        for (rule_text, input, want) in cases {
            let ops = parse_rule_line(rule_text.as_bytes(), 0).unwrap();
            assert_eq!(
                apply_rule(&ops, input).as_deref(),
                Some(&want[..]),
                "rule {rule_text:?} on {input:?}"
            );
        }
        // Outputs outside 8..=63 are filtered (but consume the index).
        let ops = parse_rule_line(b"]", 0).unwrap();
        assert_eq!(apply_rule(&ops, b"12345678"), None); // 7 < 8
        let ops = parse_rule_line(b"d d d", 0).unwrap();
        assert_eq!(apply_rule(&ops, b"12345678901234"), None); // 14*8 = 112 > 63
    }

    #[test]
    fn parse_rules_skips_comments_and_blanks() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wifilab-rules-{}", std::process::id()));
        std::fs::write(&path, "# comment\n\n:\nl\n$1\n# another\nso0\n").unwrap();
        let rules = parse_rules(&path).unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rule_count(&path).unwrap(), 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rule_iter_flatten_and_resume_continuation() {
        // 3 words × 2 rules: flattened order is word-major / rule-minor.
        let words: Vec<Vec<u8>> =
            vec![b"password".to_vec(), b"letmein1".to_vec(), b"hunter22".to_vec()];
        let rules = std::rc::Rc::new(vec![
            parse_rule_line(b":", 0).unwrap(),
            parse_rule_line(b"$1", 0).unwrap(),
        ]);
        let collect_from = |it: &mut dyn Iterator<Item = Vec<u8>>| -> Vec<Vec<u8>> { it.collect() };
        let mut full = RuleIter::new(
            Box::new(words.clone().into_iter()),
            rules.clone(),
        );
        let got = collect_from(&mut full);
        assert_eq!(
            got,
            vec![
                b"password".to_vec(),
                b"password1".to_vec(),
                b"letmein1".to_vec(),
                b"letmein11".to_vec(),
                b"hunter22".to_vec(),
                b"hunter221".to_vec(),
            ]
        );
        // Resume: skip_n(3) must continue exactly with candidate #3.
        let mut resumed = RuleIter::new(
            Box::new(words.into_iter()),
            rules,
        );
        skip_n(&mut resumed, 3);
        assert_eq!(
            collect_from(&mut resumed),
            vec![b"letmein11".to_vec(), b"hunter22".to_vec(), b"hunter221".to_vec()]
        );
    }

    #[test]
    fn hybrid_space_math_and_order() {
        // charset {0,1}, k in 1..=2: per-word = 2 + 4 = 6.
        let words: Vec<Vec<u8>> = vec![b"password".to_vec()];
        let mut it = HybridIter::new(Box::new(words.into_iter()), b"01".to_vec(), 1, 2).unwrap();
        assert_eq!(it.per_word(), 6);
        let got: Vec<Vec<u8>> = it.by_ref().collect();
        assert_eq!(
            got,
            vec![
                b"password0".to_vec(),
                b"password1".to_vec(),
                b"password00".to_vec(),
                b"password01".to_vec(),
                b"password10".to_vec(),
                b"password11".to_vec(),
            ],
            "k-blocks ascending, odometer little-endian within a block"
        );
    }

    #[test]
    fn hybrid_seek_flat_continuation() {
        // 2 words, per_word 6: full space is 12 candidates.
        let words: Vec<Vec<u8>> = vec![b"password".to_vec(), b"hunter22".to_vec()];
        let reference: Vec<Vec<u8>> =
            HybridIter::new(Box::new(words.clone().into_iter()), b"ab".to_vec(), 1, 2)
                .unwrap()
                .collect();
        assert_eq!(reference.len(), 12);
        for n in [0u64, 1, 5, 6, 7, 11] {
            let mut it =
                HybridIter::new(Box::new(words.clone().into_iter()), b"ab".to_vec(), 1, 2).unwrap();
            it.seek_flat(n);
            let got: Vec<Vec<u8>> = it.collect();
            assert_eq!(got, reference[n as usize..], "seek_flat({n})");
        }
        // Past the end: empty.
        let mut it =
            HybridIter::new(Box::new(words.into_iter()), b"ab".to_vec(), 1, 2).unwrap();
        it.seek_flat(12);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn hybrid_skips_overlong_but_consumes_index() {
        // A 63-byte word + any suffix exceeds 63 → candidates filtered,
        // but flattened slots still consumed: seeking past the first
        // word's 6 slots lands at the second word's first candidate.
        let long_word = vec![b'x'; 63];
        let words: Vec<Vec<u8>> = vec![long_word, b"password".to_vec()];
        let mut it = HybridIter::new(Box::new(words.into_iter()), b"ab".to_vec(), 1, 2).unwrap();
        it.seek_flat(6);
        assert_eq!(it.next().unwrap(), b"passworda");
    }

    #[test]
    fn freq_order_puts_common_first_and_seeks() {
        // Charset with members ranked differently in FREQ_ORDER: 'e'
        // (rank 0) precedes 'z' (absent→end) regardless of input order.
        let bf = BruteForce::new(b"ze".to_vec(), 8, 8, true).unwrap();
        let first: Vec<Vec<u8>> = bf.take(4).collect();
        assert_eq!(first[0], b"eeeeeeee");
        assert_eq!(first[1], b"eeeeeeez");
        assert_eq!(first[2], b"eeeeeeze");
        assert_eq!(first[3], b"eeeeeezz");
        // Sanitizer: the space is still a bijection (size + seek match
        // the lexicographic construction).
        let freq: Vec<Vec<u8>> = BruteForce::new(b"wze1".to_vec(), 8, 8, true).unwrap().collect();
        let mut plain: Vec<Vec<u8>> =
            BruteForce::new(b"wze1".to_vec(), 8, 8, false).unwrap().collect();
        plain.sort();
        let mut freq_sorted = freq.clone();
        freq_sorted.sort();
        assert_eq!(plain, freq_sorted, "freq_order must be a permutation");
        // seek(n) then iterate == skip n from start.
        for n in [0u64, 3, 255] {
            let mut s = BruteForce::new(b"wze1".to_vec(), 8, 8, true).unwrap();
            s.seek(n);
            let got: Vec<Vec<u8>> = s.by_ref().take(3).collect();
            assert_eq!(got, freq[n as usize..(n as usize + 3).min(freq.len())], "seek({n})");
        }
    }

    #[test]
    fn cache_skip_iter_filters_covered() {
        let words: Vec<Vec<u8>> = vec![
            b"password".to_vec(),
            b"letmein1".to_vec(),
            b"hunter22".to_vec(),
        ];
        let covered: HashSet<Box<[u8]>> = [b"letmein1".as_slice().into(), b"hunter22".as_slice().into()]
            .into_iter()
            .collect();
        let it = CacheSkipIter::new(words.into_iter(), covered);
        assert_eq!(it.collect::<Vec<_>>(), vec![b"password".to_vec()]);
        // Empty coverage = pass-through.
        let words2: Vec<Vec<u8>> = vec![b"password".to_vec()];
        let it2 = CacheSkipIter::new(words2.into_iter(), HashSet::new());
        assert_eq!(it2.count(), 1);
    }

    #[test]
    fn benchmark_cpu_half_returns_positive_hps() {
        // A ~0.1 s micro-run MUST return a positive throughput number
        // without needing a GPU.
        let hps = bench_cpu(0.1, None);
        assert!(hps > 0.0, "cpu benchmark returned {hps}");
    }

    #[test]
    fn spawn_benchmark_terminates_with_benchmark_done() {
        // Contract: exactly one BenchmarkDone terminator arrives. A GPU
        // adapter (when present) may need a while for the first dispatch,
        // so wait generously before declaring a hang.
        let (tx, rx) = crossbeam_channel::unbounded();
        let stop = spawn_benchmark(1, tx);
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut done_seen = false;
        while Instant::now() < deadline {
            match rx.recv_timeout(deadline.duration_since(Instant::now())) {
                Ok(Event::BenchmarkDone { cpu_hps, .. }) => {
                    assert!(cpu_hps > 0.0);
                    done_seen = true;
                    break;
                }
                Ok(Event::Error(e)) => panic!("benchmark error: {e}"),
                Ok(_) => {} // Log line
                Err(_) => break,
            }
        }
        assert!(done_seen, "no BenchmarkDone within 120 s");
        drop(stop);
    }
}
