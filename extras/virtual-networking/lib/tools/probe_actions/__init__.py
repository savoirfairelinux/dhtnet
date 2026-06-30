from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

from lib.core.models import ScenarioError

_REGISTERED = False


def _iter_action_modules() -> list[ModuleType]:
    modules: list[ModuleType] = []
    for module_info in sorted(pkgutil.iter_modules(__path__), key=lambda item: item.name):  # type: ignore[name-defined]
        if module_info.ispkg or module_info.name.startswith("_"):
            continue
        modules.append(importlib.import_module(f"{__name__}.{module_info.name}"))
    return modules


def register_default_probe_actions() -> None:
    global _REGISTERED
    if _REGISTERED:
        return

    for module in _iter_action_modules():
        register_actions = getattr(module, "register_actions", None)
        if register_actions is None:
            continue
        if not callable(register_actions):
            raise ScenarioError(f"{module.__name__}.register_actions must be callable")
        register_actions()
    _REGISTERED = True
