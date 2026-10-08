"""Render a ScanResult as something a human reads or a machine ingests.

Markdown for a human skimming the chains top down, json for anything that wants
to consume the result. Both are driven off the same correlated chains, so they
never disagree.
"""

from __future__ import annotations

import html
import json

from ghostsoc.engine import ScanResult


_CSS = """
body { max-width: 52rem; margin: 2rem auto; padding: 0 1rem;
  font: 15px/1.55 Georgia, "Times New Roman", serif; color: #111; background: #fff; }
h1 { font-size: 1.5rem; border-bottom: 1px solid #111; padding-bottom: .4rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #bbb; padding-bottom: .2rem; }
.meta, .asset { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
.sev { font-weight: 700; }
.note { margin: .6rem 0; padding-left: 1rem; border-left: 2px solid #111; }
ul { padding-left: 1.1rem; }
li { margin: .25rem 0; }
.desc { color: #444; font-size: 13px; }
"""


def _esc(text: str) -> str:
    return html.escape(str(text))


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
        if c.note:
            lines.append("")
            lines.append(f"> {c.note}")
        lines.append("")
        for f in c.findings:
            ref = f" ({f.references[0]})" if f.references else ""
            lines.append(f"- **{f.severity}** {f.tool}: {f.title}{ref}")
            if f.description:
                lines.append(f"  {f.description}")
        lines.append("")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>ghostsoc report: {_esc(result.target)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>ghostsoc report: {_esc(result.target)}</h1>",
        f'<p class="meta">Ran {_esc(", ".join(result.ran) or "nothing")} in '
        f"{round(result.finished - result.started, 2)}s.</p>",
    ]
    if not result.chains:
        out.append("<p>No findings.</p></body></html>")
        return "\n".join(out)
    for i, c in enumerate(result.chains, 1):
        out.append(f'<h2>{i}. <span class="asset">{_esc(c.asset)}</span></h2>')
        out.append(f'<p><span class="sev">{c.severity}</span> &middot; {_esc(", ".join(c.tools))}</p>')
        out.append(f"<p>{_esc(c.rationale)}.</p>")
        if c.note:
            out.append(f'<p class="note">{_esc(c.note)}</p>')
        out.append("<ul>")
        for f in c.findings:
            desc = f'<br><span class="desc">{_esc(f.description)}</span>' if f.description else ""
            out.append(f'<li><span class="sev">{f.severity}</span> {_esc(f.tool)}: {_esc(f.title)}{desc}</li>')
        out.append("</ul>")
    out.append("</body></html>")
    return "\n".join(out)


_RENDER = {"md": to_markdown, "json": to_json, "html": to_html}


def write(result: ScanResult, path: str, fmt: str = "md") -> None:
    text = _RENDER.get(fmt, to_markdown)(result)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
