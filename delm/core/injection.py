"""Prompt-injection detection — heuristic, deterministic, no-LLM.

The threat: an *untrusted source* (a document an agent reads) may contain
**injected instructions** aimed at the agent itself — "ignore previous
instructions", "exfiltrate this to...", "overwrite the context", "act as a
different role". If such a source is admitted and later *unfolded* into a
gist that the solver reasons over, the injection can steer the agent.

We detect injections **at admission time**, on the source text, with a
deterministic pattern scan (fast, cheap, testable). The verdict drives the
taint model: an injected source is *tainted*, and any gist derived from it
is *quarantined* (its blast radius is capped by the taint model).

This is a **heuristic detector**, not a classifier: it catches the common,
high-signal injection shapes. It is intentionally conservative — a false
positive just quarantines a gist (safe, recoverable); a false negative is
mitigated by the taint model (the gist is still *marked* as untrusted even if
the detector misses it, so downstream can refuse to act on it).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- pattern catalogue (case-insensitive) -------------------------------
# Each entry: (id, compiled regex). A match on any = the text is flagged.

_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    # "ignore / disregard / override your (previous) instructions"
    ("ignore-instructions",
     re.compile(r"\b(ignore|disregard|overlook|override|discard)\b.*\b"
                r"(all\s+)?(previous|prior|earlier|above|original|system|your)"
                r".{0,20}\b(instructions?|prompts?|rules?|guidelines?)\b", re.I)),
    # "do not follow / stop following / you must now"
    ("stop-following",
     re.compile(r"\b(do\s+not\s+follow|stop\s+following|no\s+longer\s+follow)"
                r".{0,30}\b(instructions?|rules?|guidelines?)\b", re.I)),
    # "you are / you must now be / act as / pretend to be <role>"
    ("role-hijack",
     re.compile(r"\b(you\s+are\s+now|you\s+must\s+now\s+be|act\s+as|pretend\s+"
                r"to\s+be|role\s*[:\-]\s*\w+|new\s+persona|switch\s+to\s+the\s+"
                r"role)\b", re.I)),
    # "reveal / dump / print / show your (system) prompt / instructions"
    ("prompt-extraction",
     re.compile(r"\b(reveal|dump|print|show|repeat|output)\b.{0,25}\b"
                r"(system\s+)?(prompt|instructions?|seed|preamble)\b", re.I)),
    # "exfiltrate / send / upload / post / share ... to <url|endpoint>"
    ("exfiltration",
     re.compile(r"\b(exfiltrate|exfiltration|send|upload|post|share|transmit|"
                r"leak|forward)\b.{0,40}\b(to|at|into|via)\b.{0,20}"
                r"(https?://|api\.|/webhook|endpoint|server|domain|url)", re.I)),
    # "overwrite / replace / modify / edit the (shared) context / memory"
    ("context-override",
     re.compile(r"\b(overwrite|override|replace|modify|edit|rewrite|append\s+"
                r"to|delete|remove|clear)\b.{0,30}\b(the\s+)?(shared\s+)?"
                r"(context|memory|state|ledger|gist|blackboard)\b", re.I)),
    # "execute / run / launch / invoke <command> / system call"
    ("command-exec",
     re.compile(r"\b(execute|run|launch|invoke|call|trigger)\b.{0,30}\b"
                r"(command|shell|script|system\s+call|curl|bash|python|eval|"
                r"import\s+os)\b", re.I)),
    # "reveal / print / show the (api) key / secret / token / password"
    ("secret-extraction",
     re.compile(r"\b(reveal|dump|print|show|output|leak)\b.{0,25}\b"
                r"(api\s+)?(key|secret|token|password|credential|private\s+key)"
                r"\b", re.I)),
    # "ignore everything above / above is wrong / above is a lie"
    ("above-invalidation",
     re.compile(r"\b(above|previous|earlier)\b.{0,20}\b(is\s+)(wrong|a\s+lie|"
                r"fake|invalid|not\s+true|disregarded)\b", re.I)),
    # "from now on / going forward / as of now, you will"
    ("behavior-reset",
     re.compile(r"\b(from\s+now\s+on|going\s+forward|as\s+of\s+now|effective"
                r"\s+immediately|henceforth)\b.{0,30}\b(you\s+(will|must)"
                r"|\bdo\b)", re.I)),
]


@dataclass(frozen=True)
class InjectionVerdict:
    """Outcome of scanning one text for injected instructions."""
    clean: bool
    matched: tuple[str, ...] = ()      # ids of the patterns that fired
    snippets: tuple[str, ...] = ()     # short excerpts around each match

    @property
    def reasons(self) -> str:
        if self.clean:
            return "no injected-instruction pattern matched"
        return "matched: " + ", ".join(self.matched)


def _snippet(text: str, start: int, end: int, width: int = 60) -> str:
    s = max(0, start - 15)
    e = min(len(text), end + 15)
    return text[s:e].replace("\n", " ")


def detect_injection(text: str) -> InjectionVerdict:
    """Scan *text* for injected-instruction patterns.

    Returns an :class:`InjectionVerdict`. ``clean`` is True when no pattern
    fired. ``matched`` lists the pattern ids that did fire; ``snippets``
    holds short excerpts around each match (for audit).
    """
    if not text:
        return InjectionVerdict(clean=True)
    matched: list[str] = []
    snippets: list[str] = []
    for pid, rx in _PATTERNS:
        for m in rx.finditer(text):
            matched.append(pid)
            snippets.append(_snippet(text, m.start(), m.end()))
    if not matched:
        return InjectionVerdict(clean=True)
    # de-dup pattern ids (a pattern may fire multiple times)
    seen = list(dict.fromkeys(matched))
    return InjectionVerdict(clean=False, matched=tuple(seen),
                            snippets=tuple(snippets[:8]))


__all__ = ["InjectionVerdict", "detect_injection"]
