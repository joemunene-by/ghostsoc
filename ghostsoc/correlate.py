"""Turn a pile of findings from many tools into something a human can read.

Two jobs: collapse the same finding seen more than once, and group what is left
by the asset it concerns so the engine can rank per asset rather than per line.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ghostsoc.findings import Finding, Severity


_ROLES = {
    "attack-surface": "exposure",
    "recon": "exposure",
    "web": "exposure",
    "data-leak": "secret",
    "secrets": "secret",
    "dast": "vuln",
    "sast": "vuln",
}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with the same fingerprint, keeping the loudest.

    The same exposed service shows up in both a recon pass and a port scan; the
    same secret shows up on every rerun. We keep one, lift it to the highest
    severity any tool gave it, and union the evidence and references.
    """
    by_print: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint
        kept = by_print.get(fp)
        if kept is None:
            by_print[fp] = f
            continue
        if f.severity > kept.severity:
            f.evidence = {**kept.evidence, **f.evidence}
            f.references = _union(kept.references, f.references)
            by_print[fp] = f
        else:
            kept.evidence = {**f.evidence, **kept.evidence}
            kept.references = _union(kept.references, f.references)
    return list(by_print.values())


def by_asset(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.asset].append(f)
    return dict(groups)


@dataclass
class Chain:
    asset: str
    findings: list[Finding]
    severity: Severity
    rationale: str
    tools: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "severity": str(self.severity),
            "rationale": self.rationale,
            "note": self.note,
            "tools": self.tools,
            "findings": [f.to_dict() for f in self.findings],
        }


def chain(findings: list[Finding]) -> list[Chain]:
    """Group findings by the asset they share and lift the ones that escalate.

    A leaked credential is a High on its own. A leaked credential on a host a
    recon pass already flagged as an exposed service is a different animal: the
    key unlocks something reachable. When findings on one asset span two of
    exposure, secret and vuln, we raise the chain a band and say why.
    """
    chains: list[Chain] = []
    for root, group in _by_root(findings).items():
        roles = {_ROLES.get(f.category, "other") for f in group}
        escalating = roles & {"exposure", "secret", "vuln"}
        base = max(f.severity for f in group)
        if len(escalating) >= 2:
            severity = Severity(min(int(base) + 1, int(Severity.CRITICAL)))
            rationale = _explain(escalating, group)
        else:
            severity = base
            rationale = group[0].title if len(group) == 1 else f"{len(group)} findings on {root}"
        chains.append(
            Chain(
                asset=root,
                findings=sorted(group, key=lambda f: f.severity, reverse=True),
                severity=severity,
                rationale=rationale,
                tools=sorted({f.tool for f in group}),
            )
        )
    chains.sort(key=lambda c: c.severity, reverse=True)
    return chains


def _by_root(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[_root(f.asset)].append(f)
    return dict(groups)


def _root(asset: str) -> str:
    """Reduce an asset to the thing two tools would both name: the host.

    recon says `api.example.com`, dlp says `api.example.com` for a secret in a
    config, a SARIF result says `config.yaml:12`. We strip a trailing :port or
    :line and any url scheme and path so those line up on the host where they can.
    """
    value = asset
    if "://" in value:
        value = value.split("://", 1)[1].split("/", 1)[0]
    if ":" in value:
        head, tail = value.rsplit(":", 1)
        if tail.isdigit():
            value = head
    return value


def _explain(roles: set[str], group: list[Finding]) -> str:
    by_role: dict[str, Finding] = {}
    for f in group:
        role = _ROLES.get(f.category, "other")
        if role not in by_role or f.severity > by_role[role].severity:
            by_role[role] = f
    parts = [f"{by_role[r].tool} found {by_role[r].title.lower()}" for r in sorted(roles) if r in by_role]
    return " and ".join(parts) + " on the same asset"


def _union(a: list[str], b: list[str]) -> list[str]:
    seen = list(a)
    for item in b:
        if item and item not in seen:
            seen.append(item)
    return seen
