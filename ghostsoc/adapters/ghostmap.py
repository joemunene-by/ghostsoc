"""Adapter for ghostmap, the web app vulnerability scanner (XSS, SQLi).

ghostmap emits SARIF, so it is a thin SarifAdapter: name it, point it at the
binary and arguments, and from_sarif does the rest.
"""

from __future__ import annotations

from ghostsoc.adapters.base import register
from ghostsoc.adapters.sarif import SarifAdapter


@register
class GhostMapAdapter(SarifAdapter):
    name = "ghostmap"
    binary = "ghostmap"
    categories = ("web", "dast")
    args = ("--sarif", "--url")
