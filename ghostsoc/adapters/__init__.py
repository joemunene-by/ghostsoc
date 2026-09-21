from ghostsoc.adapters.base import (
    Adapter,
    AdapterError,
    all_adapters,
    get_adapter,
    register,
)
from ghostsoc.adapters import ghostrecon, ghostdlp, ghostmap  # noqa: F401  (register on import)

__all__ = ["Adapter", "AdapterError", "all_adapters", "get_adapter", "register"]
