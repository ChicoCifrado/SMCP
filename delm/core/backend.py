"""What a serving node actually exposes, discovered rather than configured.

Every backend in this space advertises an OpenAI-compatible surface and stops
there. That is the floor, not the ceiling:

============  ============================  ==================
backend       OpenAI                        Anthropic
============  ============================  ==================
Ollama        chat, responses, models       no
LM Studio     models, responses, chat,      no
              embeddings, completions
SGLang        full ``/v1``, logit bias,     no
              thinking, LoRA, JSON schema
llama.cpp     chat, responses, embeddings   yes
vLLM          the widest: chat, responses,  yes
              embeddings, audio, realtime,  (+ count_tokens)
              rerank, classify, score
LocalAI       chat + images + audio         yes
============  ============================  ==================

So a node that speaks only OpenAI is a different kind of node from one that
also speaks ``/v1/messages``, and that difference is worth knowing before
spending a request on it. Hence discovery: probe, record what answered, and
sign the result.

Why the surface is signed rather than trusted. Probing a node is exactly the
``nodeAdvertisesModel`` situation: a list the node itself produced. Unsloth's
``/v1/models`` carries ``quant``, three context lengths and a ``loaded`` flag;
its ``/v1/status`` carries ``supports_tools``, ``supports_reasoning``,
``is_vision``, ``is_mlx``, ``requires_trust_remote_code``. A standard OpenAI
client sees ``object: model`` and ``id`` and cannot tell a real 27B GPU from a
node claiming one. Everything worth forging lives in fields the standard
client silently ignores.

Signing the surface does not make any of it true. It makes it
*attributable* — a node that lied is a node that lied, and is traceable. That
is the same bargain as :mod:`capability`, and it is why ``declared`` is the
word used throughout rather than ``detected`` or ``available``.

One field carries its own warning. ``unified_memory`` (Unsloth reports
``is_mlx``) means a Mac shares RAM between CPU and GPU, so a "24 GB GPU" is
memory the rest of the system also wants. :meth:`Surface.safe_vram_gb`
discounts it rather than reporting the headline number, because a node claiming
16 GB of shared memory has, by construction, less than 16 GB available to a
model.

What this deliberately does not do: rank, reserve, or schedule. That is
:mod:`telemetry` and :mod:`placement`. This module answers one question — what
is on the other end — and hands the rest a signed answer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .provenance import KeyPair, verify_public
from .x402 import b64u_decode, b64u_encode, canonical_json

__all__ = [
    "ENDPOINTS",
    "BackendKind",
    "ModelListing",
    "ServiceSurface",
    "SignedSurface",
    "probe_transport",
    "known_backend",
    "surface_hints",
    "model_ids",
]

# --- endpoint paths, keyed by canonical name -------------------------------
# Only paths worth *routing* are here. Anything else a backend exposes is
# recorded by the probe but not named, because naming it would imply this
# module knows what it does.

ENDPOINTS: dict[str, str] = {
    # OpenAI-compatible: the floor almost every backend provides.
    "models": "/v1/models",
    "chat": "/v1/chat/completions",
    "completions": "/v1/completions",
    "responses": "/v1/responses",
    "embeddings": "/v1/embeddings",
    # Anthropic Messages API: present in vLLM, llama.cpp, LocalAI, and
    # Unsloth's Studio backend. Absent in Ollama, LM Studio and SGLang.
    "messages": "/v1/messages",
    "count_tokens": "/v1/messages/count_tokens",
    # Not standard OpenAI. LM Studio documents these; Unsloth's backend
    # exposes the first two, which is how we tell a real llmfit-capable
    # service from a bare OpenAI shim.
    "status": "/v1/status",
    "model_detail": "/v1/models/{model_id}",
    # Ollama's native API. Not OpenAI at all, and the only non-/v1 prefix
    # worth carrying: a node speaking only this is an Ollama, and its model
    # listing is richer than the compatible one.
    "native_models": "/api/tags",
    "health": "/health",
}


class BackendKind:
    """Named shapes of surface, so callers can reason without string checks."""

    OPENAI_ONLY = "openai-only"
    OPENAI_ANTHROPIC = "openai+anthropic"
    NATIVE_OLLAMA = "ollama-native"
    UNKNOWN = "unknown"


#: ``owned_by`` to canonical name. Only the two worth naming: the rest of the
#: ecosystem reports a vendor string that varies by version.
_HINT_BY_OWNER = {
    "unsloth-studio": "unsloth",
    "lm studio": "lmstudio",
}

#: Endpoints whose presence distinguishes a node from a bare OpenAI shim.
_DISTINGUISHING = frozenset({"messages", "responses", "status", "native_models"})


def known_backend(name: str) -> str | None:
    """Canonical backend name for a signature, or ``None`` if unrecognised.

    Detection is a convenience for display. It never gates anything: an
    unrecognised surface still reports exactly what answered, and an adversary
    cannot escape the signature by returning something exotic.
    """
    n = (name or "").strip().lower()
    table = {
        "ollama": BackendKind.NATIVE_OLLAMA,
        "lmstudio": BackendKind.OPENAI_ONLY,
        "lm-studio": BackendKind.OPENAI_ONLY,
        "sglang": BackendKind.OPENAI_ONLY,
        "llamacpp": BackendKind.OPENAI_ANTHROPIC,
        "llama.cpp": BackendKind.OPENAI_ANTHROPIC,
        "vllm": BackendKind.OPENAI_ANTHROPIC,
        "localai": BackendKind.OPENAI_ANTHROPIC,
        "unsloth": BackendKind.OPENAI_ANTHROPIC,
    }
    return table.get(n)


@dataclass(frozen=True)
class ModelListing:
    """One entry from ``/v1/models``, keeping what the standard drops.

    ``context_length`` and ``quant`` are extensions. An OpenAI client ignores
    them, so a node can claim any of it without affecting a client that routes
    on ``id`` alone. Keeping them here is what lets the ranking see that.
    """

    id: str
    owned_by: str = ""
    created: int = 0
    quant: str = ""
    context_length: int = 0
    max_context_length: int = 0
    native_context_length: int = 0
    loaded: bool | None = None

    #: Context to plan against. ``max_context_length`` when present because it
    #: is the ceiling the model was trained for; the smaller ``context_length``
    #: is what the server currently allows.
    @property
    def effective_context(self) -> int:
        return self.max_context_length or self.context_length or self.native_context_length

    @classmethod
    def from_payload(cls, d: Any) -> "ModelListing | None":
        if not isinstance(d, dict):
            return None
        mid = d.get("id")
        if not isinstance(mid, str) or not mid:
            return None
        def _i(key: str) -> int:
            try:
                return int(d.get(key) or 0)
            except (TypeError, ValueError):
                return 0
        loaded = d.get("loaded")
        return cls(
            id=mid,
            owned_by=str(d.get("owned_by") or ""),
            created=_i("created"),
            quant=str(d.get("quant") or ""),
            context_length=_i("context_length"),
            max_context_length=_i("max_context_length"),
            native_context_length=_i("native_context_length"),
            loaded=bool(loaded) if isinstance(loaded, bool) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "owned_by": self.owned_by,
            "created": self.created,
            "quant": self.quant,
            "context_length": self.context_length,
            "max_context_length": self.max_context_length,
            "native_context_length": self.native_context_length,
        }
        if self.loaded is not None:
            d["loaded"] = self.loaded
        return d


@dataclass(frozen=True)
class ServiceSurface:
    """What answered, and what the node says about itself.

    Every field here is the node's own claim. ``declared_only`` is set when the
    probe could confirm *reachability* but not the claims themselves, which is
    the normal case: ``/v1/status`` is a self-report with nothing behind it
    that a probe could check.
    """

    #: Endpoints confirmed to answer, by canonical name.
    endpoints: frozenset[str] = frozenset()
    #: Endpoints probed and absent. Kept distinct from "not probed", because
    #: "absent" is evidence and "unknown" is not.
    absent: frozenset[str] = frozenset()
    models: tuple[ModelListing, ...] = ()
    backend_hint: str = ""
    owner: str = ""
    #: Fields lifted from ``/v1/status``. Declared, never verified.
    declared: dict[str, Any] = field(default_factory=dict)
    #: True when at least one endpoint answered, i.e. the host is a live
    #: service. False for an unreachable port.
    reachable: bool = False

    def has(self, name: str) -> bool:
        return name in self.endpoints

    @property
    def kind(self) -> str:
        if "native_models" in self.endpoints and not (
            self.endpoints & frozenset({"chat", "messages"})
        ):
            return BackendKind.NATIVE_OLLAMA
        if "messages" in self.endpoints:
            return BackendKind.OPENAI_ANTHROPIC
        if self.endpoints & frozenset({"chat", "responses", "models"}):
            return BackendKind.OPENAI_ONLY
        return BackendKind.UNKNOWN

    @property
    def declared_only(self) -> bool:
        """Everything in :attr:`declared` is unverifiable from outside.

        Named rather than folded away, because a caller that wants to rank on
        ``supports_tools`` needs to know it is ranking on a claim.
        """
        return bool(self.declared)

    def safe_vram_gb(self, declared_vram_gb: float | None) -> float | None:
        """Plan against this number, not the headline one.

        On unified memory the CPU and GPU share the same pool, so the full
        figure is not available to a model. A node reporting 24 GB of shared
        memory has less than 24 GB free, and planning against the headline is
        how a plan gets admitted and then fails at run time.

        The discount is deliberately blunt. It is a floor on how much of a
        shared pool one model may claim, not a measurement.
        """
        if declared_vram_gb is None:
            return None
        if self._unified():
            return round(declared_vram_gb * 0.5, 2)
        return declared_vram_gb

    def _unified(self) -> bool:
        if self.declared.get("is_mlx"):
            return True
        if str(self.backend_hint).strip().lower() == "mlx":
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        # Explicit annotations: pyright widens `sorted(self.endpoints)` to a
        # byte-ish iterable when the source is a bare frozenset default, and
        # the dict ordering has to be stable anyway because it is what gets
        # signed.
        endpoints: list[str] = sorted(self.endpoints)
        absent: list[str] = sorted(self.absent)
        declared: dict[str, Any] = {k: self.declared[k]
                                    for k in sorted(self.declared)}
        return {
            "endpoints": endpoints,
            "absent": absent,
            "models": [m.to_dict() for m in self.models],
            "backend_hint": self.backend_hint,
            "owner": self.owner,
            "declared": declared,
            "reachable": self.reachable,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class SignedSurface:
    """:class:`ServiceSurface` plus the node's signature over it.

    Split from the surface itself so an unsigned discovery (a local probe of
    your own machine) is still usable, while anything that travels the mesh is
    expected to be signed. :func:`verify_surface` refuses an unsigned one.
    """

    surface: ServiceSurface
    author_id: str = ""
    signature: str = ""
    observed_at: float = 0.0
    #: Algorithm the signature was made with. Carried with the signature
    #: rather than assumed, because ``verify_public`` needs it to pick the
    #: right primitive — and assuming "ed25519" would silently reject an
    #: hmac-identified node, or worse, accept it under the wrong check.
    sig_kind: str = "ed25519"

    def payload(self) -> dict[str, Any]:
        return {
            "kind": "surface",
            "v": 1,
            "author": self.author_id,
            "observed_at": round(float(self.observed_at), 3),
            "surface": self.surface.to_dict(),
        }

    def digest(self) -> str:
        """SHA-256 over the canonical JSON of :meth:`payload`.

        Same construction as :class:`delm.core.roster.Endorsement`: sorted keys,
        no whitespace, UTF-8. ``digest_of`` is deliberately *not* used — it is
        for signed gists, which have a label and a body, and it reaches for
        attributes this envelope does not have.
        """
        return hashlib.sha256(canonical_json(self.payload())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "author": self.author_id,
            "signature": self.signature,
            "sig_kind": self.sig_kind,
            "observed_at": round(float(self.observed_at), 3),
            "surface": self.surface.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignedSurface":
        s = d.get("surface") or {}
        models = tuple(
            m for m in (
                ModelListing.from_payload(x) for x in s.get("models") or []
            ) if m is not None
        )
        surface = ServiceSurface(
            endpoints=frozenset(s.get("endpoints") or ()),
            absent=frozenset(s.get("absent") or ()),
            models=models,
            backend_hint=str(s.get("backend_hint") or ""),
            owner=str(s.get("owner") or ""),
            declared=dict(s.get("declared") or {}),
            reachable=bool(s.get("reachable", False)),
        )
        return cls(
            surface=surface,
            author_id=str(d.get("author") or ""),
            signature=str(d.get("signature") or ""),
            observed_at=float(d.get("observed_at") or 0.0),
            sig_kind=str(d.get("sig_kind") or "ed25519"),
        )

    def sign(self, key: KeyPair) -> "SignedSurface":
        """Sign with the node's key — the one from the mesh handshake.

        Signing with a fresh key per probe would be worse than useless: it
        would produce a valid signature proving nothing about who is speaking,
        which is the same mistake as the gist that auto-registered whatever key
        the payload happened to carry.
        """
        unsigned = SignedSurface(self.surface, key.author_id, "",
                                 self.observed_at, key.kind)
        return SignedSurface(self.surface, key.author_id,
                             b64u_encode(key.sign(unsigned.digest())),
                             self.observed_at, key.kind)

    def verified(self, keyring: dict[str, bytes]) -> bool:
        """Whether the node's key signed exactly this surface.

        Recomputed from the received payload, so editing ``endpoints`` after
        the fact invalidates it — the same rule as signed contexts.
        """
        if not self.author_id or not self.signature:
            return False
        pub = keyring.get(self.author_id)
        if pub is None:
            return False
        return verify_public(self.sig_kind, pub, self.digest(),
                             b64u_decode(self.signature))


# --------------------------------------------------------------------------
# probing
# --------------------------------------------------------------------------
#: The probe order. ``models`` first because a live OpenAI-compatible server
#: answers it with no parameters; the rest are tried only once that succeeded,
#: so a host that is not an LLM server is dismissed after one request.
_PROBE_ORDER = (
    "models", "chat", "messages", "responses", "status",
    "completions", "embeddings", "native_models", "health",
)

#: Anthropic's token counter. Not in the default order: it only exists where
#: ``messages`` exists, so probing it on its own spends a request to learn
#: nothing. Callers that care add it explicitly.
_OPTIONAL_ORDER = ("count_tokens",)

#: Probes safe to ask with GET and no body. Everything else goes out as POST
#: with a minimal payload.
#:
#: Note the 405 handling below: a route that exists but dislikes the verb is
#: recorded as *present*, because a 405 is the server telling us the path is
#: real. Recording that as absent would make a capable node look narrower than
#: it is, and the surface is the thing this module exists to report honestly.
_GET_ONLY = frozenset({"models", "status", "native_models", "health"})


def probe_transport(
    fetch: Any,
    *,
    probe_names: tuple[str, ...] = _PROBE_ORDER,
    get_names: "frozenset[str]" = _GET_ONLY,
) -> ServiceSurface:
    """Discover a surface through an injected ``fetch``.

    ``fetch(name, path, method)`` returns ``(status, body_text)``. Injecting it
    keeps this module free of any HTTP client, which is the same discipline
    :mod:`delm.core.x402` follows — and it means the probe logic is testable
    against a hostile backend without opening a socket.

    A route that answers 405 to a GET is treated as **present**: the server
    told us the path exists and dislikes our verb. Recording that as absent
    would make a fully capable node look narrower than it is, and a node's
    surface is exactly what this module exists to report honestly.
    """
    endpoints: set[str] = set()
    absent: set[str] = set()
    models: tuple[ModelListing, ...] = ()
    declared: dict[str, Any] = {}
    owner = ""
    backend_hint = ""
    reachable = False

    for name in probe_names:
        path = ENDPOINTS.get(name)
        if path is None:
            continue
        method = "GET" if name in get_names else "POST"
        status, body = fetch(name, path, method)
        if status is None:
            # Transport failure: the host is not answering at all.
            absent.add(name)
            continue
        if 200 <= status < 300:
            reachable = True
            endpoints.add(name)
            parsed = _json_or_none(body)
            if name == "models":
                found, owner = _parse_models(parsed)
                models = found
                owner = owner or ""
            elif name == "native_models":
                found2, _ = _parse_ollama_tags(parsed)
                models = models or found2
            elif name == "status":
                declared = _interesting_status(parsed)
            continue
        if status in (404, 501):
            absent.add(name)
            continue
        if status == 405:
            # The route exists; we simply used the wrong verb.
            reachable = True
            endpoints.add(name)
            parsed = _json_or_none(body)
            if name == "models":
                found, owner_from_405 = _parse_models(parsed)
                models = models or found
                owner = owner or owner_from_405
            continue
        absent.add(name)

    hint = str(declared.get("backend") or "").strip()
    if not hint:
        # Fall back to the OpenAI `owned_by`, which is all an OpenAI-only
        # backend has to identify itself with.
        hint = _HINT_BY_OWNER.get(owner.strip().lower(), "")
    return ServiceSurface(
        endpoints=frozenset(endpoints),
        absent=frozenset(absent),
        models=models,
        backend_hint=hint,
        owner=owner,
        declared=declared,
        reachable=reachable,
    )


def _json_or_none(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _parse_models(payload: Any) -> tuple[tuple[ModelListing, ...], str]:
    if not isinstance(payload, dict):
        return (), ""
    data = payload.get("data")
    if not isinstance(data, list):
        return (), ""
    out = []
    owner = ""
    for entry in data:
        m = ModelListing.from_payload(entry)
        if m is not None:
            out.append(m)
            owner = owner or m.owned_by
    return tuple(out), owner


def _parse_ollama_tags(payload: Any) -> tuple[tuple[ModelListing, ...], str]:
    """Ollama's native listing: ``{"models": [{"name": ..., "size": ...}]}``."""
    if not isinstance(payload, dict):
        return (), ""
    data = payload.get("models")
    if not isinstance(data, list):
        return (), ""
    out = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        if not isinstance(name, str) or not name:
            continue
        out.append(ModelListing(id=name,
                                owned_by="ollama",
                                quant=str(entry.get("digest") or "")[:16]))
    return tuple(out), ""


#: Only self-reported fields worth carrying into a ranking decision. The full
#: ``/v1/status`` payload runs to dozens of keys, most of them UI settings.
_STATUS_KEEP = (
    "supports_tools", "supports_reasoning", "reasoning_style",
    "is_vision", "is_audio", "has_video_input", "is_diffusion", "is_mlx",
    "unified_memory", "context_length", "max_context_length",
    "native_context_length", "context_length_enforced",
    "requires_trust_remote_code", "supports_preserve_thinking",
)


def _interesting_status(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    out: dict[str, Any] = {}
    for key in _STATUS_KEEP:
        if key in payload:
            out[key] = payload[key]
    return out


# --------------------------------------------------------------------------
# bridge to what already exists
# --------------------------------------------------------------------------
def surface_hints(surface: ServiceSurface) -> dict[str, Any]:
    """Model/context facts a caller can hand to llmfit and placement.

    Deliberately a *hint* and nothing more. :mod:`delm.core.llmfit` owns the
    question "does this model fit this host" and :mod:`delm.core.placement`
    owns "which peers cover it"; both already read a
    :class:`~delm.core.llmfit.SystemProfile` and a
    :class:`~delm.core.placement.ModelSpec`. This module does not re-estimate
    memory or re-decide placement — it only surfaces what the node said about
    its own context window and quantisation, which neither of those can know
    from outside.

    The values are the node's claims. ``declared_only`` on the surface is the
    flag that says so, and a caller that wants certainty has to go and look.
    """
    hints: dict[str, Any] = {}
    if surface.models:
        widest = max(surface.models, key=lambda m: m.effective_context)
        if widest.effective_context:
            hints["max_context_length"] = widest.effective_context
        if widest.context_length:
            hints["context_length"] = widest.context_length
        quants = sorted({m.quant for m in surface.models if m.quant})
        if quants:
            hints["quants"] = quants
        if any(m.loaded for m in surface.models):
            hints["has_loaded_model"] = True
    if surface.declared.get("max_context_length"):
        hints["declared_max_context_length"] = surface.declared[
            "max_context_length"]
    return hints


def model_ids(surface: ServiceSurface) -> tuple[str, ...]:
    """Declared model ids, sorted, deduplicated.

    This is the list a routing decision would be made against, and it is
    exactly the ``nodeAdvertisesModel`` situation: a list the node produced.
    Signed, yes — attested, no. Routing on it means trusting the node's word
    about what it can load, which is the standing limitation of the whole
    capability layer and not something this helper can fix.
    """
    return tuple(sorted({m.id for m in surface.models if m.id}))
