from __future__ import annotations

import argparse
import sys

from ghostsoc import __version__
from ghostsoc.adapters import all_adapters
from ghostsoc.engine import scan


def _cmd_adapters(args: argparse.Namespace) -> int:
    for adapter in sorted(all_adapters(), key=lambda a: a.name):
        mark = "ready" if adapter.available() else "missing"
        cats = ", ".join(adapter.categories) or "-"
        print(f"{adapter.name:14} {mark:8} {cats}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    only = [s.strip() for s in args.only.split(",")] if args.only else None
    result = scan(args.target, only=only)
    if result.skipped:
        print(f"skipped (not installed): {', '.join(result.skipped)}", file=sys.stderr)
    if not result.chains:
        print(f"no findings on {args.target}")
        return 0
    print(f"{args.target}: {len(result.chains)} assets, ran {', '.join(result.ran)}\n")
    for c in result.chains:
        print(f"[{c.severity}] {c.asset}")
        print(f"    {c.rationale}")
        for f in c.findings:
            print(f"      - {f.tool}: {f.title} ({f.severity})")
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ghostsoc", description="drive the ghostsuite, correlate, report")
    parser.add_argument("--version", action="version", version=f"ghostsoc {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("adapters", help="list adapters and whether their tool is installed").set_defaults(
        func=_cmd_adapters
    )

    p_scan = sub.add_parser("scan", help="scan a target with every available adapter")
    p_scan.add_argument("target")
    p_scan.add_argument("--only", help="comma-separated adapter names to run instead of all")
    p_scan.set_defaults(func=_cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
