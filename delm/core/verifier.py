"""Verifier — admission-time verification (paper §A.3).

A :class:`Verifier` checks that a proposed update is actually grounded in its
supporting evidence before it may be admitted into the shared context. Two
paths mirror the paper:

  * **Trajectory check** — a reasoning result ``r`` is compressed to a gist
    ``G``; the verifier asks whether ``G`` faithfully captures the finding /
    failure / constraint in ``r`` (no new, unsupported claims).
  * **Source check** — a source unit ``u`` yields a reference-grounded
    summary ``S`` (each bullet carries a :class:`RefTag`); the verifier
    checks each bullet's head/tail appears verbatim in ``u`` (the
    "admission-time" grounding gate), and that the gist ``G`` does not
    contradict ``S``.

The default implementation is a deterministic, LLM-free verifier
(:class:`RuleVerifier`) so the framework is testable and reproducible without
an API key. A :class:`LLMVerifier` wraps an :class:`LLMClient` for
production use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


def _to_text(obj: Any) -> str:
    """Coerce a payload value to plain text.

    Accepts ``str`` or a :class:`Gist` (uses its ``.gist`` text). Keeps the
    verifier robust to either the raw string or the structured gist object.
    """
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    gist_text = getattr(obj, "gist", None)
    if isinstance(gist_text, str):
        return gist_text
    return str(obj)


class Verifier(Protocol):
    """Interface for admission-time verification."""

    async def verify(
        self,
        kind: str,
        payload: dict[str, Any],
    ) -> "VerifyResult":
        """Return a :class:`VerifyResult` for one proposed update.

        ``kind`` is ``"trajectory"`` or ``"source"``. ``payload`` is
        verifier-specific; for ``source`` it must include ``raw`` (the source
        unit) and ``summary`` (the :class:`Summary`), and for ``trajectory``
        it must include ``result`` (the raw trajectory text) and ``gist``.
        """
        ...


@dataclass
class VerifyResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    # For source verification: the per-bullet grounding outcomes, so a
    # failed bullet can be routed to a targeted rewrite (paper §A.3).
    bullet_report: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reasons": list(self.reasons),
            "bullet_report": list(self.bullet_report),
        }


class RuleVerifier:
    """Deterministic, key-free verifier.

    * Source: each summary bullet's ``RefTag`` (head/tail) must appear, in
      order and verbatim, in the raw unit. Bullets that fail are reported
      (and, if ``strict``, cause the whole update to be rejected).
    * Trajectory: the gist must not introduce *new concrete claims* that are
      absent from the trajectory text. We approximate "grounded" by requiring
      that every *long token n-gram* (>= 4 words) in the gist also appears in
      the trajectory. This is a cheap proxy for faithfulness that needs no
      model.
    """

    def __init__(self, min_ngram_words: int = 4, strict_source: bool = True) -> None:
        self.min_ngram_words = min_ngram_words
        self.strict_source = strict_source

    # ------------------------------------------------------------ source
    async def verify(self, kind: str, payload: dict[str, Any]) -> VerifyResult:
        if kind == "source":
            return self._verify_source(payload)
        if kind == "trajectory":
            return self._verify_trajectory(payload)
        raise ValueError(f"unknown verify kind {kind!r}")

    def _verify_source(self, payload: dict[str, Any]) -> VerifyResult:
        raw: str = payload.get("raw", "")
        summary = payload.get("summary")
        reasons: list[str] = []
        report: list[dict[str, Any]] = []
        n_fail = 0
        for i, bullet in enumerate(getattr(summary, "claims", []) or []):
            claim = bullet.get("claim", "")
            ref = bullet.get("ref")
            ok = False
            why = ""
            if ref is None:
                why = "missing RefTag"
            else:
                head, tail = ref.head, ref.tail
                h_ok = head and head in raw
                t_ok = tail and tail in raw
                # order check: head must appear before tail in the raw unit
                order_ok = (head in raw and tail in raw
                            and raw.find(head) < raw.find(tail))
                ok = h_ok and t_ok and order_ok
                if not ok:
                    why = "RefTag head/tail not found verbatim & in order in raw"
            n_fail += 0 if ok else 1
            report.append({"index": i, "claim": claim, "ok": ok, "why": why})
        if n_fail:
            reasons.append(f"{n_fail} bullet(s) failed grounding")
        ok = (n_fail == 0) if self.strict_source else True
        return VerifyResult(ok=ok, reasons=reasons, bullet_report=report)

    # -------------------------------------------------------- trajectory
    def _verify_trajectory(self, payload: dict[str, Any]) -> VerifyResult:
        result: str = _to_text(payload.get("result", ""))
        gist: str = _to_text(payload.get("gist", ""))
        res_ngrams = self._ngrams(result, self.min_ngram_words)
        gist_ngrams = self._ngrams(gist, self.min_ngram_words)
        ungrounded = [g for g in gist_ngrams if g not in res_ngrams]
        if ungrounded:
            return VerifyResult(
                ok=False,
                reasons=[f"{len(ungrounded)} gist n-gram(s) not grounded in trajectory"],
            )
        return VerifyResult(ok=True)

    # ------------------------------------------------------------- utils
    @staticmethod
    def _ngrams(text: str, n: int) -> set[str]:
        words = text.lower().split()
        if len(words) < n:
            return {text.lower()} if text.strip() else set()
        return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


class LLMVerifier:
    """Model-backed verifier.

    Wraps an :class:`LLMClient` and asks it to judge grounding. Used when
    deterministic checks are insufficient (e.g. semantic drift). The prompt
    is kept model-agnostic; swap the client to target any OpenAI-compatible
    endpoint.
    """

    def __init__(self, llm: "LLMClient") -> None:
        self.llm = llm

    async def verify(self, kind: str, payload: dict[str, Any]) -> VerifyResult:
        if kind == "source":
            prompt = (
                "You are an admission verifier. Decide whether the summary "
                "bullets are each grounded in the raw source. Respond with "
                "JSON: {\"ok\": bool, \"reasons\": [str]}. Raw source:\n"
                + payload.get("raw", "") +
                "\nSummary bullets:\n" +
                "\n".join(b.get("claim", "") for b in (payload.get("summary").claims or []))
            )
        else:
            prompt = (
                "You are an admission verifier. Decide whether the gist is "
                "faithful to the trajectory (no unsupported claims). Respond "
                "with JSON: {\"ok\": bool, \"reasons\": [str]}. Trajectory:\n"
                + payload.get("result", "") +
                "\nGist:\n" + payload.get("gist", "")
            )
        import json
        try:
            raw = await self.llm.complete(prompt)
            data = json.loads(raw)
            return VerifyResult(
                ok=bool(data.get("ok", False)),
                reasons=list(data.get("reasons", [])),
            )
        except Exception as e:  # noqa: BLE001 - fall back to a safe reject
            return VerifyResult(ok=False, reasons=[f"verifier error: {e}"])
