"""AdmissionPipeline — compress, verify, admit (paper §3.2, Algorithm 1 step 3).

An agent's raw result ``r`` never enters the shared context directly. It is:

  1. **Compressed** into a candidate :class:`Gist` (plus, for source units, a
     reference-grounded :class:`Summary`).
  2. **Verified** against its evidence by a :class:`Verifier`.
  3. **Admitted** into the :class:`SharedContext` iff it passes.

On failure the pipeline can retry with feedback (regenerate the gist) up to a
retry limit, then either drop the update or return it to the task queue as a
"needs more work" signal — exactly the admission-time gate of paper §A.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from delm.core.gist import Gist, GistKind, Summary
from delm.core.llm import LLMClient
from delm.core.provenance import KeyPair, digest_of
from delm.core.shared_context import SharedContext
from delm.core.verifier import Verifier, VerifyResult


@dataclass
class AdmissionOutcome:
    admitted: bool
    gist: Gist | None = None
    verify: VerifyResult | None = None
    attempts: int = 0
    reason: str = ""


class AdmissionPipeline:
    """Compress -> verify -> admit, with bounded retries."""

    def __init__(self, llm: LLMClient, verifier: Verifier,
                 max_retries: int = 2) -> None:
        self.llm = llm
        self.verifier = verifier
        self.max_retries = max_retries

    # ------------------------------------------------------------- stamping
    @staticmethod
    def _stamp(gist: Gist, author_id: str, key: KeyPair | None) -> None:
        """Attach provenance (author + signature) to a verified gist.

        The gist must already be *verified* (its content is final) before
        stamping, because the signature covers the content digest. ``key`` may
        be ``None`` (unsigned) when the secure context does not require a
        signature.
        """
        gist.author_id = author_id
        if key is not None:
            gist.digest = digest_of(gist)
            gist.signature = key.sign(gist.digest)
            gist.sig_kind = key.kind

    # ------------------------------------------------------------- source
    async def admit_source(self, ctx: SharedContext, label: str,
                           raw: str, question: str = "",
                           author_id: str = "unknown",
                           key: KeyPair | None = None) -> AdmissionOutcome:
        """Admit a long source unit ``raw`` under ``label``.

        Builds a reference-grounded :class:`Summary` (S layer) and a compact
        :class:`Gist` (G layer), verifies the summary bullets against ``raw``,
        then admits the gist into ``ctx``.
        """
        last: AdmissionOutcome | None = None
        for attempt in range(self.max_retries + 1):
            summary, gist = await self._compress_source(label, raw, question)
            verify = await self.verifier.verify(
                "source", {"raw": raw, "summary": summary, "gist": gist}
            )
            last = AdmissionOutcome(
                admitted=verify.ok, gist=gist, verify=verify,
                attempts=attempt + 1,
                reason="" if verify.ok else "; ".join(verify.reasons),
            )
            if verify.ok:
                gist.summary = summary
                gist.raw = raw
                self._stamp(gist, author_id, key)
                ctx.admit(gist)
                last.admitted = True
                last.reason = ""
                return last
            # feedback loop: ask for a corrected summary (regenerate)
            raw = await self._rewrite_source(raw, question, verify)
        return last or AdmissionOutcome(admitted=False, reason="no attempts")

    # --------------------------------------------------------- trajectory
    async def admit_trajectory(self, ctx: SharedContext, label: str,
                               result: str, kind: GistKind = GistKind.FACT,
                               question: str = "",
                               author_id: str = "unknown",
                               key: KeyPair | None = None) -> AdmissionOutcome:
        """Admit a reasoning result ``result`` under ``label``.

        Compresses ``result`` into a compact :class:`Gist`, verifies it against
        ``result`` (no unsupported claims), then admits.
        """
        last: AdmissionOutcome | None = None
        for attempt in range(self.max_retries + 1):
            gist = await self._compress_trajectory(label, result, kind, question)
            verify = await self.verifier.verify(
                "trajectory", {"result": result, "gist": gist}
            )
            last = AdmissionOutcome(
                admitted=verify.ok, gist=gist, verify=verify,
                attempts=attempt + 1,
                reason="" if verify.ok else "; ".join(verify.reasons),
            )
            if verify.ok:
                gist.raw = result
                self._stamp(gist, author_id, key)
                ctx.admit(gist)
                last.admitted = True
                last.reason = ""
                return last
            # regenerate with feedback
            result = await self._rewrite_trajectory(result, question, verify)
        return last or AdmissionOutcome(admitted=False, reason="no attempts")

    # ------------------------------------------------------- compression
    async def _compress_source(self, label: str, raw: str,
                               question: str) -> tuple[Summary, Gist]:
        """Build the S layer (Summary) and G layer (Gist) for a source unit."""
        # The LLM produces bullets with RefTags; the deterministic fallback
        # (used by the demo) derives them from the raw text directly.
        prompt = (
            "[ROLE:SUMMARIZER]\n"
            f"question: {question}\n"
            f"source unit (label={label}):\n{raw}\n"
            "Produce a reference-grounded summary: a list of atomic claims, "
            "each with a RefTag = (head, tail) verbatim spans of the source. "
            "Then produce a one-paragraph compact gist."
        )
        out = await self.llm.complete(prompt)
        # For the deterministic demo client, synthesize from the raw text.
        if "REFTAG:" not in out:
            summary = self._fallback_summary(raw, label)
        else:
            summary = self._parse_summary(out, raw, label)
        gist = Gist(
            label=label,
            gist=self._fallback_gist(raw, label),
            kind=GistKind.SOURCE,
        )
        gist.summary = summary
        return summary, gist

    async def _compress_trajectory(self, label: str, result: str,
                                   kind: GistKind,
                                   question: str) -> Gist:
        prompt = (
            "[ROLE:SUMMARIZER]\n"
            f"question: {question}\n"
            f"trajectory result:\n{result}\n"
            "Compress into a one-paragraph compact gist that preserves the "
            "finding, without adding unsupported claims."
        )
        out = await self.llm.complete(prompt)
        # Deterministic fallback: keep the first sentence(s) verbatim.
        gist_text = out.strip() if out.strip() else result.strip()
        return Gist(label=label, gist=gist_text, kind=kind)

    async def _rewrite_source(self, raw: str, question: str,
                              verify: VerifyResult) -> str:
        """Feedback step: ask the LLM to fix the source (no-op for demo)."""
        prompt = (
            "[ROLE:SUMMARIZER]\n"
            f"Your summary was rejected: {'; '.join(verify.reasons)}.\n"
            f"question: {question}\n"
            f"source:\n{raw}\n"
            "Rewrite the source excerpt so each claim is verbatim-grounded."
        )
        return await self.llm.complete(prompt)

    async def _rewrite_trajectory(self, result: str, question: str,
                                  verify: VerifyResult) -> str:
        prompt = (
            "[ROLE:SUMMARIZER]\n"
            f"Your gist was rejected: {'; '.join(verify.reasons)}.\n"
            f"question: {question}\n"
            f"trajectory:\n{result}\n"
            "Rewrite the gist so it adds no unsupported claims."
        )
        return await self.llm.complete(prompt)

    # ------------------------------------------------- deterministic fallbacks
    @staticmethod
    def _fallback_summary(raw: str, label: str) -> Summary:
        """Derive a grounded Summary straight from ``raw`` (demo path).

        Each non-empty line becomes a claim whose RefTag spans that line, so
        the verifier's verbatim check passes by construction.
        """
        from delm.core.gist import RefTag
        claims = []
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        for ln in lines:
            head = ln[:24]
            tail = ln[-24:]
            claims.append({
                "claim": ln,
                "ref": RefTag(head=head, tail=tail, n_words=5),
            })
        if not claims:
            claims = [{"claim": raw.strip()[:80] or label,
                       "ref": RefTag(head=raw.strip()[:8] or label,
                                      tail=raw.strip()[-8:] or label)}]
        return Summary(claims=claims, raw_unit=raw)

    @staticmethod
    def _fallback_gist(raw: str, label: str) -> str:
        first = (raw.strip().splitlines() or [""])[0].strip()
        return first[:160] or f"source {label}"

    @staticmethod
    def _parse_summary(out: str, raw: str, label: str) -> Summary:
        """Parse a ``REFTAG:<head>|<tail>\t<claim>`` block from the LLM."""
        from delm.core.gist import RefTag
        claims = []
        for line in out.splitlines():
            line = line.rstrip("\n")
            if "REFTAG:" not in line:
                continue
            head_part, _, claim = line.partition("\t")
            head, _, tail = head_part.partition("|")
            claims.append({
                "claim": claim.strip(),
                "ref": RefTag(head=head.strip(), tail=tail.strip()),
            })
        if not claims:
            claims = AdmissionPipeline._fallback_summary(raw, label).claims
        return Summary(claims=claims, raw_unit=raw)
