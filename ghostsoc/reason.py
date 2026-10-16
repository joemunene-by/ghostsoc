"""Put a sentence of judgement on each chain: what it means, what to do first.

GhostLM is the cybersecurity model this suite is built around, so when it is
reachable we let it write the note. When it is not (the common case on a laptop
with no model pulled) we fall back to a template keyed on the roles in the chain.
The fallback is deliberately plain so a scan is still useful offline.
"""

from __future__ import annotations

from ghostsoc.correlate import _ROLES, Chain

_TEMPLATES = {
    frozenset({"exposure", "secret"}): (
        "A leaked secret sits on an asset that is reachable from outside. Treat it as "
        "an active foothold: rotate the credential and close the exposure before anything else."
    ),
    frozenset({"exposure", "vuln"}): (
        "An exploitable flaw is on a reachable surface, so it is directly attackable. "
        "Patch or take the endpoint offline rather than relying on it being unknown."
    ),
    frozenset({"secret", "vuln"}): (
        "A flaw and a secret share this asset; a foothold through one hands over the other. "
        "Fix both, assume the secret is already known."
    ),
    frozenset({"exposure", "secret", "vuln"}): (
        "Exposure, a secret and an exploitable flaw all land on one asset. This is the most "
        "likely path in; work it first."
    ),
}


def triage(chains: list[Chain], use_model: bool = True) -> list[Chain]:
    model = _load_model() if use_model else None
    for c in chains:
        if model is not None:
            try:
                c.note = model(c)
                continue
            except Exception:
                pass
        c.note = _fallback(c)
    return chains


def _fallback(chain: Chain) -> str:
    roles = frozenset(_ROLES.get(f.category, "other") for f in chain.findings) & {
        "exposure",
        "secret",
        "vuln",
    }
    return _TEMPLATES.get(roles, chain.rationale.capitalize() + ".")


def _load_model():
    """Return a callable that notes a chain, or None if GhostLM is not available."""
    try:
        from ghostlm.serve import local_client  # type: ignore
    except Exception:
        return None

    client = local_client()

    def note(chain: Chain) -> str:
        prompt = (
            "You are a SOC analyst. In one or two sentences, say what this correlated "
            f"finding means and what to do first.\nAsset: {chain.asset}\nSeverity: {chain.severity}\n"
            + "\n".join(f"- {f.tool}: {f.title} ({f.severity})" for f in chain.findings)
        )
        return client.generate(prompt, max_tokens=120).strip()

    return note
