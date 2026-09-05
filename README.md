# DELM — Decentralized Language Models (clean-room implementation)

A clean-room implementation of the coordination core of **DELM**
(Mao & Mirhoseini, *Decentralized Multi-Agent Systems with Shared Context*,
arXiv:2606.10662). It captures the load-bearing mechanisms, not the
SWE-bench/LongBench harnesses:

> Instead of a central orchestrator that routes every intermediate result
> through itself (a communication bottleneck), agents coordinate
> **decentrally** through two global structures:
>
> - a **shared context** `C` — compact, *verified* gists of accumulated
>   progress, visible to every agent; and
> - a **task queue** `T` — pending subtasks agents claim asynchronously.
>
> An agent claims a task, reads `C`, does local reasoning, and writes back a
> compact update that is **compressed, verified against its evidence, and
> admitted** into `C` only if it passes. Intermediate progress becomes
> *reusable problem state*.

This package is self-contained and runnable with **no API key** (a
deterministic `FakeLLMClient` drives the demo and the test suite). Point it
at a real model via `OpenAICompatibleClient` for production use.

## Install

```bash
cd /mnt/d/Hermes/DeLM/delm
pip install -e .
```

Python 3.11+.

## Quickstart (no API key)

```bash
python -m delm.demo.run_demo
# or:
delm-demo
```

Output:

```
=== DELM end-to-end demo (no API key) ===
queue exhausted : True
admitted gists  : ['u1/w0', 'u2/w1', 'u3/w2', 'u4/w3']
per-worker adm  : {0: 1, 1: 1, 2: 1, 3: 1}
u3 admitted as  : u3/w2
u3 gist (trunc) : Examined u3. The load-bearing constraint is: a transaction must be journaled ...
u3 raw present  : True
final answer    : ANSWER: The task is resolved by the verified change ...
=== demo OK ===
```

The demo drives the **full** pipeline end to end: a 4-unit corpus is seeded
into the task queue; 4 parallel workers each claim one unit, reason locally,
and their results pass the **admission gate** (verified, then admitted into
the shared context); the load-bearing unit's gist is then **selectively
unfolded** (`G -> S -> raw`); and a finalizer produces the answer strictly
from the shared context.

## Run the tests

```bash
python -m pytest -q
```

The suite is split across three files, all deterministic:

- `test_delm.py` — the core mechanisms: task queue (eligibility, deps,
  double-claim, cycle detection), shared context (snapshot reads, atomic
  admit, render), admission (source RefTag grounding, trajectory n-gram
  faithfulness), unfolding (`G -> S -> raw`), and the full pipeline + demo.
- `test_security.py` — Capas 1+2: canonical digest, ed25519/HMAC sign/verify,
  trust gate, the four secure-context guarantees (gate / signature /
  integrity / immutability), the hash-chained ledger, and that
  `DelmPipeline` really routes through the secure context and signs.
- `test_taint.py` — Capa 5: the injection detector, the three taint levels,
  transitive closure, and that the pipeline ships the anti-injection layer
  by default.

## Architecture

```
delm/
  core/
    gist.py            Gist, Summary, RefTag, GistKind   (the data model)
    shared_context.py  SharedContext                      (the verified C)
    task_queue.py      TaskQueue, Task                    (the dependency-aware T)
    admission.py       AdmissionPipeline                  (compress->verify->admit)
    verifier.py        RuleVerifier, LLMVerifier, VerifyResult
    unfolding.py       Unfolding                          (G -> S -> raw)
    llm.py             LLMClient, FakeLLMClient, OpenAICompatibleClient
    pipeline.py        Worker, DelmPipeline               (the decentralized loop)
  demo/
    run_demo.py        end-to-end demo (no API key)
tests/
    test_delm.py       unit + e2e tests
```

### The five mechanisms

1. **Shared context (`SharedContext`)** — the verified state `C`. Only
   admitted gists live here. Reads are **lock-free snapshots**; writes are
   **atomic** (write-before-publish: backing `Summary`/raw is written before
   the visible gist is appended). This is the paper's "concurrent admission
   with disciplined reads and writes" (§A.4).

2. **Task queue (`TaskQueue`)** — the dependency-aware queue `T`. Tasks carry
   `[deps: ...]`; a task is eligible only when its deps are done. `claim()`
   is the single serialization point (a task already `RUNNING`/`DONE` cannot
   be re-claimed). `cycle_check()` guards against dependency cycles.

3. **Admission (`AdmissionPipeline`)** — the gate. A raw result `r` never
   enters `C` directly. It is (a) **compressed** into a candidate `Gist`
   (+ a reference-grounded `Summary` for source units), (b) **verified**
   against its evidence by a `Verifier`, and (c) **admitted** iff it passes.
   On failure it retries with feedback, then drops or returns to the queue
   (paper §A.3).

4. **Selective unfolding (`Unfolding`)** — coarse-to-fine, on-demand. Agents
   read the compact gist layer by default; when they need detail they
   `unfold` (`G -> S`) or `deep_unfold` (`S -> raw`). Unfolded content is
   *local to the requesting call* — it is **not** written back into `C`, so
   the gist layer stays clean for the other agents. Raw retrieval is
   neighborhood-aware (`n` returns `n±1`).

5. **The decentralized loop (`Worker` / `DelmPipeline`)** — N workers race on
   the shared queue; each claims a task, reads a snapshot of `C`, reasons
   locally, and routes the result through admission. When the queue
   exhausts, the last worker may `generate_more` (enqueue fresh subtasks) or
   finalize. There is **no** central orchestrator merging results — that is
   the whole point.

### Verification

The default gate is `RuleVerifier` (deterministic, key-free):

- **Source path** — each `Summary` bullet's `RefTag` (head/tail) must appear,
  in order and verbatim, in the raw unit. A failed bullet is reported and,
  under `strict_source`, rejects the update.
- **Trajectory path** — the gist must not introduce claims absent from the
  trajectory; approximated by requiring every long token n-gram of the gist
  to also appear in the trajectory.

Swap in `LLMVerifier` (or a hybrid) for production; the pipeline does not
care which implements the gate.

### Using a real model

```python
import asyncio
from delm.core.llm import OpenAICompatibleClient
from delm.core.pipeline import DelmPipeline
from delm.core.task_queue import Task

async def main():
    llm = OpenAICompatibleClient(
        model="google/gemini-3-flash",          # any OpenAI-compatible id
        base_url="https://openrouter.ai/api/v1",
        api_key="sk-...",
    )
    pipe = DelmPipeline(llm=llm, n_workers=4)
    tasks = [Task(label=f"t{i}", body="...", kind="solve") for i in range(8)]
    out = await pipe.run(tasks)
    print(out.answer)

asyncio.run(main())
```

`OpenAICompatibleClient` targets any OpenAI-compatible endpoint (OpenRouter,
a direct provider, or a local server) — the same `model` / `base_url` /
`api_key` shape as the reference repo's `config/model_config.yaml`.

## Design notes

- **No central orchestrator.** The reference paper's ablation shows the gains
  come from a *verified shared state* plus a *decentralized queue*, not from
  more parallel agents. This implementation isolates exactly those two
  structures.
- **Write-before-publish.** Backing content is written before the visible
  gist is appended, so any agent that can see a label can also resolve its
  backing stores — no torn reads.
- **Unfolded content is not re-published.** Detailed `S`/raw is local to the
  requesting call; it never pollutes `C`.
- **Model-agnostic.** The framework talks to an `LLMClient`; `FakeLLMClient`
  proves the wiring, `OpenAICompatibleClient` runs it for real.

## Security (Capas 1+2 — provenance and integrity)

The shared context is the *memory of every agent*, so its integrity is the
primary threat. This project hardens it with a provenance layer modeled on
MeshLLM's integrity rules (size + SHA-256, immutable refs, trust policy)
applied to the **content** plane:

- **Canonical digest** (`delm/core/provenance.py`) — a stable SHA-256 over a
  gist's *content* (order-independent, excludes the signature fields). The
  digest is the identity of what an agent admits.
- **Signature** — each agent signs its gist's digest with an **ed25519** key
  (real asymmetric crypto via `cryptography`), falling back to an HMAC
  pre-shared key if `cryptography` is absent.
- **Trust gate** (`delm/core/secure_context.py`) — `TrustPolicy`
  (`require-signed` / `allowlist` / `denylist`) decides who may write.
- **Immutability** — re-admitting an existing label is only allowed if the
  digest is *identical* (idempotent re-verification); a digest change is a
  rejected overwrite, never a silent replace.
- **Ledger** (`delm/core/ledger.py`) — an append-only, hash-chained audit
  trail of every admit/reject, replayable via `verify_chain()`.

Run it:

```bash
python -m delm.demo.run_security_demo
```

The demo shows a legit admit, a blocked malicious agent, a rejected tamper,
and a clean ledger replay. `tests/test_security.py` locks in all four
guarantees plus the crypto round-trips.

**End-to-end by default.** `DelmPipeline` is wired to the secure context:
each worker gets its own author identity and ed25519 key, signs every gist
it admits, and the `SecureSharedContext` verifies each signature against the
registered keyring before it lands. The public end-to-end demo
(`python -m delm.demo.run_demo`) therefore already runs *with* provenance —
`tests/test_security.py::test_pipeline_uses_secure_context_and_signs` asserts
the pipeline really uses the secure context and that every admitted gist
carries a valid signature, so the layer can't be silently disabled.

> This is the *content-plane* hardening. The *transport-plane* rules
> (QUIC/iroh end-to-end encryption, Nostr/mDNS discovery, signed bootstrap
> tokens, owner control-plane) apply only when DELM is deployed
> multi-node; that layer is intentionally not built yet.

## Security (Capa 5 — anti prompt-injection)

The shared context is also the *input* of every agent's reasoning. A
**prompt injection** — an untrusted source that carries instructions aimed at
the agent ("ignore previous instructions", "reveal your prompt", "exfiltrate
to ...") — can steer every agent that reads it. Capa 5 contains that blast
radius with a **deterministic, no-LLM** detector plus a **taint model**:

- **Detector** (`delm/core/injection.py`) — a pattern scan over the admitted
  text (role-hijack, prompt-extraction, exfiltration, context-override,
  command-exec, ...). It is a *heuristic*, not a classifier: a false positive
  only quarantines a gist (safe, recoverable); a false negative is still
  contained because the taint model marks the source untrusted regardless.
- **Taint model** (`delm/core/taint.py`) — three levels:
  - `CLEAN` — no taint; rendered normally.
  - `SUSPICIOUS` — one pattern matched; *quarantined*: still visible, but
    rendered framed as **untrusted data, not instructions**.
  - `CONFIRMED` — `injection_threshold` (default 2) or more patterns;
    *blocked*: omitted from the agent-visible render.
- **Transitive closure** — taint is attached to the *source*, and any gist
  *derived from* a tainted source inherits the level
  (`TaintRegistry.derived_level`). A single poisoned source cannot spread
  under many labels: `u4` derived from a `CONFIRMED` `u3` is itself
  `CONFIRMED`.

The quarantine lives in `SecureSharedContext.render()`: `CONFIRMED` gists are
omitted, `SUSPICIOUS` gists are framed, `CLEAN` gists render as before. The
**detector scans both the gist text and the raw source** — the raw is the
untrusted input, and an injection can live there and be paraphrased away from
the compressed gist, so scanning the gist alone would miss it. The quarantine
also applies to **selective unfolding**: a `CONFIRMED` gist's raw is withheld
from `deep_unfold` (the raw is the most dangerous injection vector), so a
blocked source cannot be read back through the unfold path. `DelmPipeline`
ships it **by default** (`injection_threshold=2`); the admission path scans
every admitted gist and `taint_report()` exposes the per-label levels for
audit.

Run it:

```bash
python -m delm.demo.run_taint_demo
```

The demo shows a multi-agent scenario: clean gists render normally, a
malicious injection is `CONFIRMED` and blocked, and a gist derived from it
inherits the block. `tests/test_taint.py` locks in the detector, the three
levels, transitive closure, and that the pipeline ships the layer by default.

## Relation to the reference repo

The reference implementation
(`github.com/yuzhenmao/DeLM`) bundles the SWE-bench and LongBench-v2 harnesses
(Docker execution, ACI tooling, `pass@N` grading) around the same core. This
project is a **clean-room** re-derivation of that core — the shared verified
context, the dependency-aware queue, admission-time verification, selective
unfolding, and the parallel workers — expressed as a small, testable library.
It is not a copy of that codebase.

## License

MIT.
