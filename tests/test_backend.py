"""Tests for backend surface discovery and its signature.

Discovery is only useful if it is honest about a node that lies, and a node
that lies is the expected case rather than the exotic one. So the fake backends
here are built to misreport: a 405 on every route, a status endpoint full of
claims, a body that is not JSON at all, and a server that answers the same
thing for everything.

The signature tests use the node's mesh key, on purpose. A surface signed by a
freshly generated key would verify perfectly and attribute nothing, which is
the same failure as the old gist that auto-registered whatever key the payload
carried.
"""

from __future__ import annotations

import json

import pytest

from delm.core import backend as be
from delm.core.provenance import KeyPair

OPENAI_MODELS = {
    "object": "list",
    "data": [
        {
            "id": "qwen3-8b",
            "object": "model",
            "created": 1700000000,
            "owned_by": "vllm",
        }
    ],
}

UNSLOTH_MODELS = {
    "object": "list",
    "data": [
        {
            "id": "unsloth/Qwen3.8-27B-GGUF",
            "object": "model",
            "created": 1790936187,
            "owned_by": "unsloth-studio",
            "quant": "UD-Q2_K_XL",
            "context_length": 131072,
            "max_context_length": 262144,
            "native_context_length": 262144,
            "loaded": True,
        }
    ],
}

UNSLOTH_STATUS = {
    "is_vision": True,
    "supports_tools": True,
    "supports_reasoning": True,
    "is_mlx": False,
    "context_length": 131072,
    "max_context_length": 262144,
    "requires_trust_remote_code": False,
    "chat_template_override": None,
    "ui_slider_position": 7,
}


def fetch_from(routes: dict[str, tuple[int, object]]):
    """A ``fetch`` backed by a route table. Unlisted paths answer 404."""

    def fetch(name: str, path: str, method: str) -> tuple[int | None, str | None]:
        if path not in routes:
            return 404, None
        status, body = routes[path]
        if body is None:
            return status, None
        return status, json.dumps(body) if not isinstance(body, str) else body

    return fetch


def probe(routes, **kw) -> be.ServiceSurface:
    return be.probe_transport(fetch_from(routes), **kw)


# --------------------------------------------------------------- discovery
def test_a_minimal_openai_server_is_discovered():
    s = probe({"/v1/models": (200, OPENAI_MODELS),
               "/v1/chat/completions": (200, {})})
    assert s.reachable is True
    assert s.has("models") and s.has("chat")
    assert s.kind == be.BackendKind.OPENAI_ONLY


def test_models_are_parsed_with_their_extensions():
    s = probe({"/v1/models": (200, UNSLOTH_MODELS),
               "/v1/chat/completions": (200, {})})
    m = s.models[0]
    assert m.id == "unsloth/Qwen3.8-27B-GGUF"
    assert m.quant == "UD-Q2_K_XL"
    assert m.context_length == 131072
    assert m.max_context_length == 262144
    assert m.loaded is True
    assert m.effective_context == 262144


def test_anthropic_support_is_detected_and_changes_the_kind():
    routes = {"/v1/models": (200, OPENAI_MODELS),
              "/v1/chat/completions": (200, {}),
              "/v1/messages": (200, {})}
    s = probe(routes)
    assert s.has("messages") is True
    assert s.kind == be.BackendKind.OPENAI_ANTHROPIC


def test_lm_studio_style_surface_is_openai_only():
    routes = {p: (200, OPENAI_MODELS if p == "/v1/models" else {})
              for p in ("/v1/models", "/v1/responses", "/v1/chat/completions",
                        "/v1/embeddings", "/v1/completions")}
    s = probe(routes)
    assert s.has("messages") is False
    assert s.kind == be.BackendKind.OPENAI_ONLY


def test_ollama_native_listing_is_recognised():
    s = probe({"/api/tags": (200, {"models": [
        {"name": "qwen3:8b", "digest": "abcdef0123456789"}]}),
        "/health": (200, {})})
    assert s.has("native_models") is True
    assert s.kind == be.BackendKind.NATIVE_OLLAMA
    assert s.models[0].id == "qwen3:8b"


def test_an_unreachable_host_is_not_reachable():
    def dead(name, path, method):
        return None, None

    s = be.probe_transport(dead)
    assert s.reachable is False
    assert s.endpoints == frozenset()
    assert s.kind == be.BackendKind.UNKNOWN


def test_absent_routes_are_distinguished_from_unprobed_ones():
    s = probe({"/v1/models": (200, OPENAI_MODELS)}, probe_names=("models", "chat"))
    assert "models" in s.endpoints
    assert "chat" in s.absent, "probe pero ausente != nunca consultado"


def test_a_405_route_exists_and_is_not_recorded_as_absent():
    """405 means the path is real and the verb was wrong.

    Recording that as absent would make a fully capable node look narrower than
    it is, and the surface is precisely what this module reports.
    """
    s = probe({"/v1/models": (405, None),
               "/v1/chat/completions": (200, {})})
    assert s.has("models") is True, "405: la ruta existe, el verbo no"
    assert "models" not in s.absent, "una ruta real no se marca ausente"
    assert s.reachable is True


def test_a_405_on_models_still_parses_the_listing_if_there_is_one():
    s = probe({"/v1/models": (405, UNSLOTH_MODELS),
               "/v1/chat/completions": (200, {})})
    assert s.models and s.models[0].quant == "UD-Q2_K_XL"
    assert s.owner == "unsloth-studio"


# ------------------------------------------------------------------ status
def test_status_claims_are_captured_but_only_the_useful_ones():
    s = probe({"/v1/models": (200, UNSLOTH_MODELS),
               "/v1/chat/completions": (200, {}),
               "/v1/status": (200, UNSLOTH_STATUS)})
    assert s.declared["supports_tools"] is True
    assert s.declared["is_vision"] is True
    assert "chat_template_override" not in s.declared, "ajenos al ranking"
    assert "ui_slider_position" not in s.declared


def test_declared_claims_are_flagged_as_declared_only():
    """The whole point: these are the node's own report.

    Nothing here is verified. Naming it keeps a caller that ranks on
    ``supports_tools`` from believing it ranked on a fact.
    """
    s = probe({"/v1/models": (200, UNSLOTH_MODELS),
               "/v1/chat/completions": (200, {}),
               "/v1/status": (200, UNSLOTH_STATUS)})
    assert s.declared_only is True
    assert be.ServiceSurface(endpoints=frozenset({"models"}),
                             reachable=True).declared_only is False


def test_a_backend_without_status_declares_nothing():
    s = probe({"/v1/models": (200, OPENAI_MODELS)})
    assert s.declared == {}


def test_a_non_json_status_body_is_survived():
    s = probe({"/v1/models": (200, OPENAI_MODELS),
               "/v1/status": (200, "<html>login</html>")})
    assert s.declared == {}
    assert s.reachable is True


def test_a_json_array_where_an_object_belongs_is_survived():
    s = probe({"/v1/models": (200, [1, 2, 3]),
               "/v1/status": (200, ["nope"])})
    assert s.models == ()
    assert s.declared == {}


# --------------------------------------------------------- unified memory
def test_unified_memory_halves_the_plannable_vram():
    """A Mac's '24 GB GPU' is RAM the rest of the system also wants.

    Planning against the headline is how a plan gets admitted and then fails at
    run time.
    """
    shared = be.ServiceSurface(endpoints=frozenset({"chat"}),
                               declared={"is_mlx": True})
    assert shared.safe_vram_gb(24.0) == 12.0


def test_a_dedicated_gpu_is_not_discounted():
    discrete = be.ServiceSurface(endpoints=frozenset({"chat"}),
                                 declared={"is_mlx": False})
    assert discrete.safe_vram_gb(24.0) == 24.0


def test_unified_memory_is_detected_from_the_backend_name_too():
    s = be.ServiceSurface(endpoints=frozenset({"chat"}), backend_hint="mlx")
    assert s.safe_vram_gb(16.0) == 8.0


def test_no_declared_vram_stays_none_rather_than_zero():
    s = be.ServiceSurface(endpoints=frozenset({"chat"}))
    assert s.safe_vram_gb(None) is None


# ------------------------------------------------------------------ signing
def node_key() -> KeyPair:
    return KeyPair.new("node-A", kind="ed25519")


def test_a_signed_surface_verifies_with_the_nodes_key():
    key = node_key()
    surface = probe({"/v1/models": (200, UNSLOTH_MODELS),
                     "/v1/chat/completions": (200, {}),
                     "/v1/messages": (200, {})})
    signed = be.SignedSurface(surface, observed_at=100.0).sign(key)
    assert signed.verified({"node-A": key.public_key}) is True
    assert signed.author_id == "node-A"


def test_editing_the_surface_after_signing_invalidates_it():
    key = node_key()
    surface = probe({"/v1/models": (200, OPENAI_MODELS)})
    signed = be.SignedSurface(surface, observed_at=100.0).sign(key)
    tampered = be.SignedSurface.from_dict({**signed.to_dict(), "surface": {
        **surface.to_dict(), "endpoints": ["models", "chat", "messages"]}})
    assert tampered.verified({"node-A": key.public_key}) is False


def test_adding_an_endpoint_after_signing_invalidates_it():
    """The attack this signature exists to stop.

    Claim a bare OpenAI surface, get it trusted, then add ``/v1/messages`` —
    or worse, add a model — and keep the old signature.
    """
    key = node_key()
    surface = probe({"/v1/models": (200, OPENAI_MODELS)})
    signed = be.SignedSurface(surface, observed_at=100.0).sign(key)
    richer = be.ServiceSurface(endpoints=surface.endpoints | {"messages"},
                               models=surface.models, reachable=True)
    forged = be.SignedSurface.from_dict({
        **signed.to_dict(), "surface": richer.to_dict()})
    assert forged.verified({"node-A": key.public_key}) is False


def test_an_unknown_author_does_not_verify():
    key = node_key()
    signed = be.SignedSurface(
        probe({"/v1/models": (200, OPENAI_MODELS)}), observed_at=1.0).sign(key)
    assert signed.verified({"someone-else": key.public_key}) is False


def test_an_unsigned_surface_does_not_verify():
    surface = probe({"/v1/models": (200, OPENAI_MODELS)})
    unsigned = be.SignedSurface(surface, author_id="node-A", observed_at=1.0)
    assert unsigned.verified({"node-A": node_key().public_key}) is False


def test_a_signature_from_a_different_key_does_not_verify():
    key = node_key()
    other = KeyPair.new("node-A", kind="ed25519")
    signed = be.SignedSurface(
        probe({"/v1/models": (200, OPENAI_MODELS)}), observed_at=1.0).sign(other)
    assert signed.verified({"node-A": key.public_key}) is False


def test_the_signature_is_stable_across_a_dict_roundtrip():
    key = node_key()
    signed = be.SignedSurface(
        probe({"/v1/models": (200, UNSLOTH_MODELS),
               "/v1/chat/completions": (200, {}),
               "/v1/status": (200, UNSLOTH_STATUS)}),
        observed_at=42.5).sign(key)
    again = be.SignedSurface.from_dict(json.loads(json.dumps(signed.to_dict())))
    assert again.digest() == signed.digest()
    assert again.verified({"node-A": key.public_key}) is True


def test_sig_kind_travels_with_the_signature():
    """Assuming ed25519 would reject an hmac node, or check it wrongly."""
    key = KeyPair.new("node-H", kind="hmac")
    signed = be.SignedSurface(
        probe({"/v1/models": (200, OPENAI_MODELS)}), observed_at=1.0).sign(key)
    assert signed.sig_kind == "hmac"
    assert signed.verified({"node-H": key.public_key}) is True
    assert be.SignedSurface.from_dict(signed.to_dict()).sig_kind == "hmac"


def test_sig_kind_is_not_inside_the_signed_payload():
    """Including it would make verification circular.

    ``verify_public`` needs the algorithm before it can check the digest, so
    the algorithm cannot also be covered by that digest.
    """
    key = node_key()
    signed = be.SignedSurface(
        probe({"/v1/models": (200, OPENAI_MODELS)}), observed_at=1.0).sign(key)
    assert "sig_kind" not in signed.payload()
    assert signed.verified({"node-A": key.public_key}) is True


# -------------------------------------------------------------- robustness
def test_a_backend_claiming_everything_is_still_reported_accurately():
    """The signature makes it attributable; it does not make it true.

    A node may claim all of it. What we guarantee is that the claim is signed
    by whoever made it.
    """
    liars = {p: (200, OPENAI_MODELS if p == "/v1/models"
                 else UNSLOTH_STATUS if p == "/v1/status" else {})
             for p in ("/v1/models", "/v1/chat/completions", "/v1/messages",
                       "/v1/responses", "/v1/embeddings", "/v1/completions",
                       "/v1/status", "/api/tags", "/health")}
    s = probe(liars)
    assert len(s.endpoints) == 9, "las 9 rutas del orden por defecto"
    assert s.kind == be.BackendKind.OPENAI_ANTHROPIC
    assert s.declared["supports_tools"] is True
    # Reported, and never asserted as fact.
    assert s.declared_only is True


def test_unknown_probe_names_are_skipped_not_fatal():
    s = be.probe_transport(fetch_from({"/v1/models": (200, OPENAI_MODELS)}),
                           probe_names=("models", "no-such-thing"))
    assert s.has("models") is True


def test_malformed_model_entries_are_dropped_not_fatal():
    s = probe({"/v1/models": (200, {"data": [
        {"id": "ok-model"}, {"object": "model"}, {"id": ""}, "not-a-dict",
        None]})})
    assert [m.id for m in s.models] == ["ok-model"]


def test_non_integer_fields_in_a_model_do_not_crash_the_probe():
    s = probe({"/v1/models": (200, {"data": [
        {"id": "m", "created": "ayer", "context_length": "mucho"}]})})
    assert s.models[0].created == 0
    assert s.models[0].context_length == 0


# ------------------------------------------------------------ known kinds
@pytest.mark.parametrize("name,expected", [
    ("vllm", be.BackendKind.OPENAI_ANTHROPIC),
    ("llama.cpp", be.BackendKind.OPENAI_ANTHROPIC),
    ("llamacpp", be.BackendKind.OPENAI_ANTHROPIC),
    ("localai", be.BackendKind.OPENAI_ANTHROPIC),
    ("unsloth", be.BackendKind.OPENAI_ANTHROPIC),
    ("sglang", be.BackendKind.OPENAI_ONLY),
    ("lmstudio", be.BackendKind.OPENAI_ONLY),
    ("lm-studio", be.BackendKind.OPENAI_ONLY),
    ("ollama", be.BackendKind.NATIVE_OLLAMA),
])
def test_known_backend_names_map_to_kinds(name, expected):
    assert be.known_backend(name) == expected


def test_an_unknown_backend_name_is_not_guessed():
    assert be.known_backend("mi-servidor-propio") is None
    assert be.known_backend("") is None
    assert be.known_backend("vllm-ish") is None, "sin prefijos generosos"


def test_the_owner_hint_identifies_unsloth_and_lm_studio():
    s = probe({"/v1/models": (200, UNSLOTH_MODELS),
               "/v1/chat/completions": (200, {})})
    assert s.backend_hint == "unsloth"
    assert be.known_backend(s.backend_hint) == be.BackendKind.OPENAI_ANTHROPIC


def test_vllm_is_identified_only_by_probing_not_by_owner():
    """vLLM reports no distinctive ``owned_by``, which is the honest reason.

    Detection is a display convenience. The signature covers what answered,
    not what we guessed from it.
    """
    s = probe({"/v1/models": (200, OPENAI_MODELS),
               "/v1/chat/completions": (200, {}),
               "/v1/messages": (200, {})})
    assert s.backend_hint == "", "no adivinamos nombre a partir de endpoints"
    assert s.owner == "vllm"


# ------------------------------------- where canonicalisation actually lives
def test_declared_dicts_from_different_sources_digest_identically():
    """Ordering is normalised in ``to_dict``, not in ``digest``.

    ``declared`` is parsed from whatever JSON the node sent, so two nodes -- or
    the same node twice -- hand over the same keys in different order. If that
    reached the digest unsorted, an attacker could reorder fields for free and
    keep the old signature. The defence is the explicit sorted rebuild in
    :meth:`ServiceSurface.to_dict`, so the test pins *that*.

    Mutating ``digest`` to a plain ``json.dumps`` also leaves the suite green,
    for the same reason: ``payload`` is built from the already-sorted ``to_dict``.
    Two independent layers, so neither mutation is visible alone. The test
    pins the layer that actually receives untrusted input, which is the parse.
    """
    key = node_key()
    routes_a = {"/v1/models": (200, UNSLOTH_MODELS),
                "/v1/status": (200, '{"supports_tools": true, "is_vision": true}')}
    routes_b = {"/v1/models": (200, UNSLOTH_MODELS),
                "/v1/status": (200, '{"is_vision": true, "supports_tools": true}')}
    a = be.SignedSurface(probe(routes_a), observed_at=1.0).sign(key)
    b = be.SignedSurface(probe(routes_b), observed_at=1.0).sign(key)
    assert a.digest() == b.digest(), "el orden de entrada no debe importar"
    assert a.verified({"node-A": key.public_key}) is True
    assert b.verified({"node-A": key.public_key}) is True


def test_the_serialised_dict_has_sorted_declared_keys():
    s = be.ServiceSurface(endpoints=frozenset({"chat"}),
                          declared={"z": 1, "a": 2}, reachable=True)
    assert list(s.to_dict()["declared"]) == ["a", "z"]


def test_endpoint_lists_are_sorted_so_the_signature_is_stable():
    s = be.ServiceSurface(endpoints=frozenset({"models", "chat", "messages"}),
                          absent=frozenset({"health", "status"}), reachable=True)
    d = s.to_dict()
    assert d["endpoints"] == ["chat", "messages", "models"]
    assert d["absent"] == ["health", "status"]
    # frozenset iteration order is not stable across runs; the list must be.
    assert s.to_dict() == d


def test_an_entirely_unsigned_object_cannot_verify():
    """No author, no signature: nothing to check, so nothing passes."""
    surface = probe({"/v1/models": (200, OPENAI_MODELS)})
    bare = be.SignedSurface(surface)
    key = node_key()
    # The keyring is populated, so a "return True" short-circuit would show up
    # here rather than being masked by the missing-key path.
    assert bare.verified({}) is False
    assert bare.verified({"node-A": key.public_key}) is False
    assert bare.verified({"node-A": key.public_key}, ) is False

    # Author present, signature empty: same thing.
    no_sig = be.SignedSurface(surface, author_id="node-A", observed_at=1.0)
    assert no_sig.verified({"node-A": key.public_key}) is False

    # Author empty, signature present.
    no_author = be.SignedSurface(surface, signature="AAAA", observed_at=1.0)
    assert no_author.verified({"node-A": key.public_key}) is False


def test_the_empty_field_guard_is_defence_in_depth_not_the_thing_that_holds():
    """Recorded honestly: the guard in ``verified`` cannot be killed alone.

    Removing the "no author, no signature" early return leaves the suite green,
    because an empty signature still fails ``verify_public``. The guard is not
    what makes an unsigned surface fail — the cryptographic check is — and this
    test says so rather than implying a coverage that mutation testing shows is
    not there.

    If ``verify_public`` were ever relaxed to tolerate empty input, this guard
    would become load-bearing, and that change would need its own test.
    """
    key = node_key()
    bare = be.SignedSurface(probe({"/v1/models": (200, OPENAI_MODELS)}))
    assert bare.author_id == "" and bare.signature == ""
    assert bare.verified({"node-A": key.public_key}) is False


def test_a_405_only_server_is_still_reachable():
    """Reachability is about the host answering, not about our verb.

    A server that answers 405 to everything is a live service with a surface
    we mis-probed. Reporting it unreachable would say "nothing is here", which
    is a different and wrong claim.
    """
    s = probe({p: (405, None) for p in
               ("/v1/models", "/v1/chat/completions", "/v1/messages")})
    assert s.reachable is True
    assert s.has("models") is True


# ------------------------------- the bridge to llmfit / placement
def test_surface_hints_surface_the_widest_context_not_the_first():
    s = probe({"/v1/models": (200, {"data": [
        {"id": "pequeno", "context_length": 8192, "max_context_length": 8192},
        {"id": "grande", "context_length": 131072, "max_context_length": 262144},
    ]})})
    h = be.surface_hints(s)
    assert h["max_context_length"] == 262144
    assert h["context_length"] == 131072


def test_surface_hints_collect_the_quants_present():
    s = probe({"/v1/models": (200, {"data": [
        {"id": "a", "quant": "Q4_K_M"}, {"id": "b", "quant": "Q4_K_M"},
        {"id": "c", "quant": "Q8_0"}, {"id": "d"}]})})
    assert be.surface_hints(s)["quants"] == ["Q4_K_M", "Q8_0"]


def test_surface_hints_report_a_loaded_model():
    loaded = probe({"/v1/models": (200, UNSLOTH_MODELS)})
    assert be.surface_hints(loaded)["has_loaded_model"] is True
    idle = probe({"/v1/models": (200, {"data": [{"id": "m", "loaded": False}]})})
    assert "has_loaded_model" not in be.surface_hints(idle)


def test_surface_hints_carry_the_declared_ceiling_separately():
    """Two context numbers, two trust levels, both kept.

    ``max_context_length`` from the model listing and the one in
    ``/v1/status`` are the same claim from two places; keeping them apart means
    a disagreement between them is visible instead of silently averaged.
    """
    s = probe({"/v1/models": (200, UNSLOTH_MODELS),
               "/v1/status": (200, UNSLOTH_STATUS)})
    h = be.surface_hints(s)
    assert h["max_context_length"] == 262144
    assert h["declared_max_context_length"] == 262144


def test_surface_hints_are_empty_for_an_unknown_surface():
    assert be.surface_hints(be.ServiceSurface()) == {}


def test_model_ids_are_sorted_and_deduplicated():
    s = probe({"/v1/models": (200, {"data": [
        {"id": "zeta"}, {"id": "alpha"}, {"id": "zeta"}]})})
    assert be.model_ids(s) == ("alpha", "zeta")


def test_model_ids_is_the_declared_list_and_nothing_more():
    """This is ``nodeAdvertisesModel``, stated plainly.

    The list is signed and therefore attributable, and it is still the node's
    own claim about what it can load. The test exists so nobody later "fixes"
    this into something that looks like verification.
    """
    liar = be.ServiceSurface(
        endpoints=frozenset({"models"}), reachable=True,
        models=(be.ModelListing(id="modelo-que-no-existe"),))
    assert be.model_ids(liar) == ("modelo-que-no-existe",)
    assert liar.declared_only is False, "sin /v1/status no hay claims que marcar"


def test_the_bridge_does_not_estimate_memory():
    """llmfit owns the memory question; this must not answer it.

    If a future change adds a vram estimate here, two code paths would be
    disagreeing about how much memory a model needs — and placement would have
    to pick one.
    """
    s = probe({"/v1/models": (200, UNSLOTH_MODELS)})
    h = be.surface_hints(s)
    assert "memory_required_gb" not in h
    assert "vram_gb" not in h
    assert not any("memory" in k or "vram" in k for k in h)


def test_the_bridge_ignores_the_surface_signature_entirely():
    """A caller may probe locally and use the hints unsigned.

    Discovery is useful before signing exists; refusing that would force every
    local diagnostic through the identity path.
    """
    s = probe({"/v1/models": (200, UNSLOTH_MODELS)})
    assert be.surface_hints(s)["max_context_length"] == 262144
