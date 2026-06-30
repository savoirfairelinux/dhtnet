from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .models import ScenarioError

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def slugify(value: str) -> str:
    cleaned = [char if char.isalnum() or char in "._-" else "-" for char in value]
    slug = "".join(cleaned).strip("-")
    return slug or "scenario"


def default_run_id(scenario: str) -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')}_{slugify(scenario)}"


def validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ScenarioError(
            "run_id must start with an ASCII letter or digit and contain only letters, digits, '.', '_' or '-'"
        )
    return run_id


def namespace_prefix(run_id: str) -> str:
    return f"vnet-{slugify(run_id)[:40]}"


def ensure_int(value: Any, *, field_name: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ScenarioError(f"Expected integer value for {field_name}, got {value!r}")


def strip_cidr(value: str) -> str:
    return value.split("/", 1)[0]
