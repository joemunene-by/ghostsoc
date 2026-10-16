"""Adapter for ghostrecon, the passive OSINT recon framework.

ghostrecon --target <t> --json emits an entity graph. We care about the leaf
entities that are exposure: live hosts, open services, subdomains, leaked
addresses. Each becomes a Finding keyed on the host or url it concerns so the
correlator can line it up against what other tools saw on the same asset.
"""

from __future__ import annotations

from ghostsoc.adapters.base import Adapter, register
from ghostsoc.findings import Finding, Severity

_SEVERITY_BY_KIND = {
    "open_service": Severity.MEDIUM,
    "exposed_admin": Severity.HIGH,
    "subdomain": Severity.LOW,
    "leaked_email": Severity.LOW,
    "host": Severity.INFO,
}


@register
class GhostReconAdapter(Adapter):
    name = "ghostrecon"
    binary = "ghostrecon"
    categories = ("recon", "attack-surface")

    def scan(self, target: str, **opts) -> list[Finding]:
        data = self.run_json(["ghostrecon", "--target", target, "--json"])
        return self.parse(data)

    def parse(self, data: object) -> list[Finding]:
        entities = data.get("entities", []) if isinstance(data, dict) else data
        findings: list[Finding] = []
        for ent in entities or []:
            kind = ent.get("kind", "host")
            asset = ent.get("value") or ent.get("host") or ent.get("url", "")
            if not asset:
                continue
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=f"recon.{kind}",
                    title=ent.get("label", kind.replace("_", " ")),
                    severity=_SEVERITY_BY_KIND.get(kind, Severity.INFO),
                    asset=asset,
                    category="attack-surface",
                    description=ent.get("detail", ""),
                    evidence={k: v for k, v in ent.items() if k not in {"kind", "value"}},
                    raw=ent,
                )
            )
        return findings
