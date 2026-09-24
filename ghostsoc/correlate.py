"""Turn a pile of findings from many tools into something a human can read.

Two jobs: collapse the same finding seen more than once, and group what is left
by the asset it concerns so the engine can rank per asset rather than per line.
"""

from __future__ import annotations

from collections import defaultdict

from ghostsoc.findings import Finding


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


def _union(a: list[str], b: list[str]) -> list[str]:
    seen = list(a)
    for item in b:
        if item and item not in seen:
            seen.append(item)
    return seen
