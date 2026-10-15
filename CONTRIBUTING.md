# Contributing

Thanks for looking. ghostsoc is young, so the shape is still moving.

## Setup

```
pip install -e .[dev]
pytest
ruff check .
```

## Adding an adapter

Most tools need very little. If the tool emits SARIF, subclass `SarifAdapter`,
set `name`, `binary` and `args`, and register it. Otherwise subclass `Adapter`,
implement `scan`, and map the tool's output onto `Finding` objects in a `parse`
method so it can be unit tested without the tool installed.

Keep an adapter honest about `available()` so the engine can skip it cleanly when
the tool is not installed.

## Style

Conventional commits (`feat(scope):`, `fix(scope):`, one sentence). Keep comments
for the non-obvious why. Run ruff and pytest before a PR.
