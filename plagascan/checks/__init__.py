# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Registro de checks. Cada módulo se registra con @register."""
from typing import Callable, Dict, List, Tuple

REGISTRY: List[Tuple[str, str, Callable]] = []


def register(category: str, description: str):
    def deco(fn: Callable) -> Callable:
        REGISTRY.append((category, description, fn))
        return fn
    return deco


def load_all() -> None:
    # El orden de importación es el orden de ejecución; `packages` va al
    # final porque reutiliza datos que dejan los checks anteriores.
    from . import ssh, accounts, filesystem, network, privesc, kernel  # noqa: F401
    from . import knownvulns, packages  # noqa: F401


def categories() -> Dict[str, str]:
    return {c: d for c, d, _ in REGISTRY}
