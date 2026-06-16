from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import ScenarioError


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


def ensure_int(value: Any, *, field_name: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ScenarioError(f"Expected integer value for {field_name}, got {value!r}")


def strip_cidr(value: str) -> str:
    return value.split("/", 1)[0]
