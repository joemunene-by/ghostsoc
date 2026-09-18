"""Adapter contract: wrap one ghostsuite tool, hand back normalized findings.

An adapter knows how to invoke its tool and how to read that tool's output into
Finding objects. It does not decide whether it should run; the engine does that.
Adapters degrade quietly: if the tool is not installed, available() is False and
the engine skips it rather than failing the whole scan.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from abc import ABC, abstractmethod

from ghostsoc.findings import Finding


class AdapterError(RuntimeError):
    pass


class Adapter(ABC):
    name: str = ""
    binary: str | None = None
    categories: tuple[str, ...] = ()

    def available(self) -> bool:
        if self.binary is None:
            return True
        return shutil.which(self.binary) is not None

    @abstractmethod
    def scan(self, target: str, **opts) -> list[Finding]:
        ...

    def run_json(self, args: list[str], timeout: int = 300) -> object:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise AdapterError(f"{self.name}: {args[0]} not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"{self.name}: timed out after {timeout}s") from exc
        if not proc.stdout.strip():
            # Some tools write their report to stderr when stdout is a tty; accept both.
            out = proc.stderr.strip()
        else:
            out = proc.stdout
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"{self.name}: output was not JSON") from exc


_REGISTRY: dict[str, type[Adapter]] = {}


def register(cls: type[Adapter]) -> type[Adapter]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} needs a name")
    _REGISTRY[cls.name] = cls
    return cls


def all_adapters() -> list[Adapter]:
    return [cls() for cls in _REGISTRY.values()]


def get_adapter(name: str) -> Adapter:
    try:
        return _REGISTRY[name]()
    except KeyError as exc:
        raise AdapterError(f"no adapter named {name!r}") from exc
