"""Generic SARIF ingest.

Half the suite already speaks SARIF 2.1.0 (ghostmap, ghostchain, ghostmobile,
ghostaudit). Rather than write an adapter each, from_sarif turns any SARIF
document into findings, and SarifAdapter wraps a tool whose output is SARIF.
"""

from __future__ import annotations

from ghostsoc.adapters.base import Adapter
from ghostsoc.findings import Finding, Severity


_LEVEL = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW, "none": Severity.INFO}


def _asset(result: dict) -> str:
    locs = result.get("locations") or []
    if not locs:
        return result.get("ruleId", "")
    phys = locs[0].get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    line = phys.get("region", {}).get("startLine")
    return f"{uri}:{line}" if line else uri


def _severity(result: dict, rule: dict) -> Severity:
    tags = (rule.get("properties", {}) or {})
    score = tags.get("security-severity")
    if score is not None:
        try:
            return Severity.parse(float(score))
        except (TypeError, ValueError):
            pass
    return _LEVEL.get(result.get("level", "warning"), Severity.MEDIUM)


def from_sarif(data: dict, tool: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        name = tool or driver.get("name", "sarif")
        rules = {r.get("id"): r for r in driver.get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            msg = result.get("message", {})
            findings.append(
                Finding(
                    tool=name,
                    rule_id=rule_id or "sarif.result",
                    title=rule.get("shortDescription", {}).get("text") or msg.get("text", rule_id),
                    severity=_severity(result, rule),
                    asset=_asset(result),
                    category=(rule.get("properties", {}) or {}).get("category", "sast"),
                    description=msg.get("text", ""),
                    references=[h.get("uri", "") for h in rule.get("helpUri", [])]
                    if isinstance(rule.get("helpUri"), list)
                    else ([rule["helpUri"]] if rule.get("helpUri") else []),
                    raw=result,
                )
            )
    return findings


class SarifAdapter(Adapter):
    """Base for tools invoked as `<binary> <args...>` that print SARIF."""

    args: tuple[str, ...] = ()

    def scan(self, target: str, **opts) -> list[Finding]:
        data = self.run_json([self.binary, *self.args, target])
        return from_sarif(data, tool=self.name)
