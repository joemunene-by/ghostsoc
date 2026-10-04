"""Render a ScanResult as something a human reads or a machine ingests.

Markdown for a human skimming the chains top down, json for anything that wants
to consume the result. Both are driven off the same correlated chains, so they
never disagree.
"""

from __future__ import annotations

import json

from ghostsoc.engine import ScanResult


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_markdown(result: ScanResult) -> str:
    lines = [f"# ghostsoc report: {result.target}", ""]
    lines.append(f"Ran {', '.join(result.ran) or 'nothing'} in {round(result.finished - result.started, 2)}s.")
    if result.skipped:
        lines.append(f"Skipped (tool not installed): {', '.join(result.skipped)}.")
    if result.errors:
        lines.append(f"Errors: {', '.join(f'{k} ({v})' for k, v in result.errors.items())}.")
    lines.append("")

    if not result.chains:
        lines.append("No findings.")
        return "\n".join(lines)

    counts: dict[str, int] = {}
    for c in result.chains:
        counts[str(c.severity)] = counts.get(str(c.severity), 0) + 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    summary = ", ".join(f"{counts[s]} {s.lower()}" for s in order if s in counts)
    lines.append(f"**{len(result.chains)} assets with findings:** {summary}.")
    lines.append("")

    for i, c in enumerate(result.chains, 1):
        lines.append(f"## {i}. {c.asset}")
        lines.append("")
        lines.append(f"**{c.severity}** &middot; {', '.join(c.tools)}")
        lines.append("")
        lines.append(c.rationale + ".")
        lines.append("")
        for f in c.findings:
            ref = f" ({f.references[0]})" if f.references else ""
            lines.append(f"- **{f.severity}** {f.tool}: {f.title}{ref}")
            if f.description:
                lines.append(f"  {f.description}")
        lines.append("")
    return "\n".join(lines)


def write(result: ScanResult, path: str, fmt: str = "md") -> None:
    text = to_json(result) if fmt == "json" else to_markdown(result)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
