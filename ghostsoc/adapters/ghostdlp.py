"""Adapter for ghostdlp, the data-leak and sensitive-data scanner.

ghostdlp scan <path> --json flags PII, financial data and secrets per file.
A hit's asset is the file it was found in, but when the file carries a host or
url (a config, an env dump) we key on that instead, which is what lets a leaked
credential chain to the service it unlocks.
"""

from __future__ import annotations

from ghostsoc.adapters.base import Adapter, register
from ghostsoc.findings import Finding, Severity

_SEVERITY_BY_CLASS = {
    "secret": Severity.HIGH,
    "credential": Severity.HIGH,
    "private_key": Severity.CRITICAL,
    "pii": Severity.MEDIUM,
    "financial": Severity.MEDIUM,
}


@register
class GhostDlpAdapter(Adapter):
    name = "ghostdlp"
    binary = "ghostdlp"
    categories = ("data-leak", "secrets")

    def scan(self, target: str, **opts) -> list[Finding]:
        data = self.run_json(["ghostdlp", "scan", target, "--json"])
        return self.parse(data)

    def parse(self, data: object) -> list[Finding]:
        hits = data.get("hits", []) if isinstance(data, dict) else data
        findings: list[Finding] = []
        for hit in hits or []:
            cls = hit.get("class", "pii")
            asset = hit.get("host") or hit.get("file", "")
            if not asset:
                continue
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=f"dlp.{cls}",
                    title=hit.get("label", f"{cls} exposure"),
                    severity=_SEVERITY_BY_CLASS.get(cls, Severity.MEDIUM),
                    asset=asset,
                    category="data-leak",
                    description=hit.get("detail", ""),
                    evidence={
                        "file": hit.get("file"),
                        "line": hit.get("line"),
                        "match": hit.get("redacted"),
                    },
                    raw=hit,
                )
            )
        return findings
