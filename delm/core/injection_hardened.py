"""Prompt-injection detection, hardened — normalization layer anti-evasion.

Drop-in enhancement for :mod:`delm.core.injection`. The baseline detector is
a plain regex catalogue over the raw text; that is trivially evaded with
zero-width chars, homoglyphs, leetspeak, accents, per-letter spacing or by
splitting the payload across lines. This module flattens those evasions
*before* the same pattern catalogue runs, so the false-negative surface
shrinks without adding an LLM (determinism and zero cost are preserved).

Normalization pipeline (all deterministic, pure):

1. strip zero-width / invisible chars (ZWSP, ZWNJ, ZWJ, BOM, word joiner,
   bidi controls, soft hyphen);
2. NFKD + drop combining marks (folds accents; fullwidth Latin digits and
   letters also fold here, because they are Unicode compatibility forms);
3. lowercase;
4. homoglyph folding with a *reduced* confusables table (Cyrillic and
   Greek lookalikes mapped onto their ASCII aliases). The table is not
   exhaustive: only characters that visually alias ASCII letters are
   mapped, anything else passes through unchanged;
5. leetspeak folding (0->o, 3->e, 4->a, 5->s, 7->t, @->a, $->s, ...);
6. whitespace handling: single newlines/tabs become single spaces (so
   line-split payloads are flattened for the catalogue), and runs of 2+
   spaces (double spaces, blank lines) collapse to exactly TWO spaces.
   Single spaces are kept because they may be *inside* a letter-spaced
   word ("i g n o r e"); the wide gaps left as double spaces delimit word
   boundaries, so step 7 joins word by word instead of chaining the
   sentence into one token;
7. spaced-word collapse: runs of single letters separated by exactly ONE
   space or hyphen ("i g n o r e", "i-g-n-o-r-e") join into their word
   form. The run regex captures the WHOLE run in a single group and the
   replacement strips the separators from that group — no repeated capture
   groups, so no middle letters are lost;
8. region scan (worst case): a payload where *every* word is letter-spaced
   with single spaces is one unsegmentable run for step 7. The detector
   finds maximal runs of 6+ single-spaced letters in the pre-collapse text
   and checks each *region* — compacted — against ordered keyword
   signatures. The scan is region-bounded: a legitimate document that
   merely contains "send" and a URL in different paragraphs has no spaced
   region and is never compacted, so the false-positive surface of a
   global despaced scan does not exist here.

Then the baseline catalogue from :mod:`delm.core.injection` runs over the
normalized text, and any region-signature hits are merged into the verdict.

Design notes:

* A false positive here still only *quarantines* a gist (recoverable), same
  as the baseline; the normalization cannot make things worse than the taint
  model already tolerates.
* ``evasion_detected`` is True when at least one matched pattern was NOT in
  the baseline verdict: exactly the set of payloads the baseline would have
  missed (A/B telemetry).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from delm.core.injection import _PATTERNS, detect_injection

# 1) zero-width / invisible characters ------------------------------------
_ZW = dict.fromkeys(map(ord, (
    "\u200b"  # ZWSP
    "\u200c"  # ZWNJ
    "\u200d"  # ZWJ
    "\ufeff"  # BOM / zero-width no-break space
    "\u2060"  # word joiner
    "\u2066\u2067\u2068\u2069"  # bidi isolates
    "\u00ad"  # soft hyphen
    "\u200e\u200f"  # LRM / RLM
    "\ufe00\ufe01\ufe02\ufe03\ufe04\ufe05\ufe06\ufe07\ufe08\ufe09\ufe0a\ufe0b\ufe0c\ufe0d\ufe0e\ufe0f"  # variation selectors
    "\u202a\u202b\u202c\u202d\u202e"  # bidi embeddings/override
)), None)

# 4) reduced confusables table: Cyrillic + Greek lookalikes -> ASCII --------
# NOT exhaustive (only unambiguous visual aliases); anything unmapped passes
# through unchanged.
_CONFUSABLES = str.maketrans({
    # Cyrillic lowercase
    "а": "a", "б": "b", "в": "b", "е": "e", "к": "k", "м": "m",
    "н": "h", "о": "o", "п": "n", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x",
    # Greek lowercase
    "α": "a", "β": "b", "γ": "g", "δ": "d", "ε": "e", "ζ": "z",
    "η": "n", "θ": "o", "ι": "i", "κ": "k", "λ": "l", "μ": "m",
    "ν": "v", "ξ": "x", "ο": "o", "π": "p", "ρ": "r", "σ": "o",
    "τ": "t", "υ": "u", "φ": "f", "χ": "x", "ψ": "p", "ω": "w",
})

# 5) leetspeak folding ------------------------------------------------------
_LEET = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "+": "t",
    "|": "l", "(": "c", ")": "d",
})

# 7) spaced-out words: single letters separated by exactly ONE space or
# hyphen. The whole run is captured in ONE group, so no letters are lost.
# Requiring exactly one separator char stops the run at word boundaries
# that use wider gaps (which normalize to double spaces in step 6).
_SPACED_WORD = re.compile(r"\b([a-z](?:[ \-][a-z]){3,})\b")

# 8) spaced-region scan: runs of 6+ single-spaced letters in the
# pre-collapse text. Each region is compacted and checked against ordered
# keyword signatures. Region-bounded, so natural prose never triggers it.
_SPACED_REGION = re.compile(r"\b([a-z](?: [a-z]){5,})\b")

# Ordered keyword-substring signatures over a compacted region. Each entry:
# (id, (substrings...)); all must appear in order within the SAME region.
_REGION_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("ignore-instructions", ("ignore", "instruction")),
    ("disregard-instructions", ("disregard", "instruction")),
    ("ignore-prompt", ("ignore", "prompt")),
    ("reveal-prompt", ("reveal", "prompt")),
    ("dump-system-prompt", ("systemprompt",)),
    ("role-hijack", ("actas",)),
    ("exfiltration", ("send", "http")),
    ("exfiltration", ("exfiltrat",)),
    ("secret-extraction", ("apikey",)),
    ("secret-extraction", ("privatekey",)),
    ("secret-extraction", ("secretkey",)),
    ("context-override", ("overwrite", "context")),
    ("context-override", ("delete", "context")),
    ("behavior-reset", ("fromnowon",)),
]


def _fold_accents(text: str) -> str:
    """NFKD then drop combining marks (also folds fullwidth compat forms)."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed
                   if not unicodedata.combining(c))


def _pre_whitespace(text: str) -> str:
    """Steps 1-5: zero-width strip, accent fold, lowercase, homoglyphs, leet."""
    if not text:
        return ""
    t = text.translate(_ZW)                 # 1
    t = _fold_accents(t)                    # 2
    t = t.lower()                           # 3
    t = t.translate(_CONFUSABLES)           # 4
    t = t.translate(_LEET)                  # 5
    return t


def _normalize_base(t: str) -> str:
    """Step 6: whitespace normalization that keeps word-boundary information.

    Single newlines/tabs become single spaces (the catalogue's ``.*`` does
    not cross newlines, so line-split payloads must be flattened); runs of
    2+ spaces (double spaces, blank lines) collapse to exactly TWO spaces.
    Single spaces are preserved because they may be *within* a spaced-out
    word ("i g n o r e"); the wide gaps left as double spaces delimit word
    boundaries, so step 7 joins word by word instead of chaining the
    sentence into one token.
    """
    t = re.sub(r"[\t\r\n]", " ", t)   # single newline/tab -> single space
    t = re.sub(r" {2,}", "  ", t)        # wide gaps -> exactly two spaces
    return t


def _collapse_spaced(text: str) -> str:
    """Step 7: join per-letter spaced words: "i g n o r e" -> "ignore".

    The whole run is captured in a single group; the replacement strips
    spaces and hyphens from it, so every middle letter survives. Iterated
    until stable; bounded at 4 iterations as a safety guard.
    """
    for _ in range(4):
        new = _SPACED_WORD.sub(
            lambda m: m.group(1).replace(" ", "").replace("-", ""), text)
        if new == text:
            break
        text = new
    return text


def normalize(text: str) -> str:
    """Full normalization pipeline (steps 1-7). Pure, deterministic."""
    return _collapse_spaced(_normalize_base(_pre_whitespace(text)))


def _region_scan(base: str) -> tuple[list[str], list[str]]:
    """Step 8: ordered keyword signatures over compacted spaced regions.

    Runs over the *pre-collapse* text so the fully-single-spaced worst case
    (one unsegmentable run) is still reachable. Each hit is reported with
    the compacted region as its snippet, so the auditor sees the context.
    """
    hits: list[str] = []
    snippets: list[str] = []
    for m in _SPACED_REGION.finditer(base):
        compact = m.group(1).replace(" ", "")
        for sig_id, subs in _REGION_SIGNATURES:
            pos = 0
            ok = True
            for sub in subs:
                idx = compact.find(sub, pos)
                if idx < 0:
                    ok = False
                    break
                pos = idx + len(sub)
            if ok:
                hits.append(sig_id)
                snippets.append(compact[:60])
    return hits, snippets


@dataclass(frozen=True)
class HardenedVerdict:
    """Verdict of the hardened detector.

    Same shape as :class:`InjectionVerdict`, plus:

    * ``normalized_text`` — what the catalogue actually saw (auditable).
    * ``evasion_detected`` — True when at least one matched pattern was NOT
      in the baseline verdict: the payloads the baseline would have missed.
    * ``baseline_clean`` — the raw-text baseline verdict, for A/B telemetry.
    * ``region_hits`` — signature ids caught only by the spaced-region scan.
    """
    clean: bool
    matched: tuple[str, ...] = ()
    snippets: tuple[str, ...] = ()
    normalized_text: str = ""
    evasion_detected: bool = False
    baseline_clean: bool = True
    region_hits: tuple[str, ...] = ()

    @property
    def reasons(self) -> str:
        if self.clean:
            return "no injected-instruction pattern matched (hardened)"
        tag = " [evasion]" if self.evasion_detected else ""
        return "matched: " + ", ".join(self.matched) + tag


def _snippet(text: str, start: int, end: int) -> str:
    s = max(0, start - 15)
    e = min(len(text), end + 15)
    return text[s:e]


def detect_injection_hardened(text: str) -> HardenedVerdict:
    """Scan *text* for injected instructions, evasion-aware.

    Runs the baseline catalogue over the normalized text (steps 1-7), plus
    the spaced-region signature scan (step 8) over the pre-collapse text,
    and reports both verdicts so callers can measure how much the
    normalization layer adds.
    """
    baseline = detect_injection(text)
    base = _normalize_base(_pre_whitespace(text))   # steps 1-6
    norm = _collapse_spaced(base)                   # step 7
    matched: list[str] = []
    snippets: list[str] = []
    for pid, rx in _PATTERNS:
        for m in rx.finditer(norm):
            matched.append(pid)
            snippets.append(_snippet(norm, m.start(), m.end()))
    region_hits, region_snips = _region_scan(base)  # step 8
    matched.extend(region_hits)
    snippets.extend(region_snips)
    if not matched:
        return HardenedVerdict(clean=True, normalized_text=norm,
                               baseline_clean=baseline.clean)
    seen = tuple(dict.fromkeys(matched))
    return HardenedVerdict(
        clean=False,
        matched=seen,
        snippets=tuple(snippets[:8]),
        normalized_text=norm,
        evasion_detected=bool(set(seen) - set(baseline.matched)),
        baseline_clean=baseline.clean,
        region_hits=tuple(dict.fromkeys(region_hits)),
    )


__all__ = ["normalize", "HardenedVerdict", "detect_injection_hardened"]
