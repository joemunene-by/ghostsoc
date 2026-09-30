"""Decide which adapters to run for a target, run them, correlate the result.

This is the thing a human or an agent calls. Everything upstream (adapters) and
downstream (correlation, reporting) is wired together here.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ghostsoc.adapters import Adapter, all_adapters, get_adapter
from ghostsoc.correlate import Chain, chain, dedupe
from ghostsoc.findings import Finding


@dataclass
class ScanResult:
    target: str
    chains: list[Chain]
    findings: list[Finding]
    ran: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    started: float = 0.0
    finished: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ran": self.ran,
            "skipped": self.skipped,
            "errors": self.errors,
            "duration": round(self.finished - self.started, 2),
            "chains": [c.to_dict() for c in self.chains],
        }


def _select(only: list[str] | None) -> list[Adapter]:
    if only:
        return [get_adapter(name) for name in only]
    return all_adapters()


def scan(target: str, only: list[str] | None = None, workers: int = 4) -> ScanResult:
    started = time.time()
    adapters = _select(only)
    ran, skipped = [], []
    raw: list[Finding] = []

    runnable = []
    for adapter in adapters:
        if adapter.available():
            runnable.append(adapter)
        else:
            skipped.append(adapter.name)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(a.scan, target): a for a in runnable}
        for future, adapter in futures.items():
            raw.extend(future.result())
            ran.append(adapter.name)

    findings = dedupe(raw)
    chains = chain(findings)
    return ScanResult(
        target=target,
        chains=chains,
        findings=findings,
        ran=ran,
        skipped=skipped,
        started=started,
        finished=time.time(),
    )
