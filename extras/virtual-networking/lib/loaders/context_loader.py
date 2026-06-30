from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.core.models import (
    ServiceSpec,
    FixtureSpec,
    ProbeSpec,
    ScenarioError,
    ScenarioSpec,
    StepSpec,
    TopologySpec,
)
from lib.core.paths import DEFAULT_STATE_ROOT, PROBE_DIR, ROOT
from .topology_loader import load_topology
from lib.core.util import namespace_prefix, slugify
from lib.tools.probe_runner import validate_probe_action

SCENARIO_FIELDS = frozenset(
    {
        "name",
        "description",
        "topology",
        "fixtures",
        "services",
        "steps",
        "notes",
    }
)

PROBE_STEP_FIELDS = frozenset(
    {
        "name",
        "probe",
        "inputs",
        "allow_failure",
    }
)
SERVICE_FIELDS = frozenset({"name", "kind", "role", "wait_s", "bootstrap_fixture"})
FIXTURE_FIELDS = frozenset({"name", "description", "kind", "options"})
PROBE_FIELDS = frozenset(
    {
        "name",
        "description",
        "required_inputs",
        "probe_sequence",
    }
)
def require_string(value: Any, *, field_name: str, scenario_path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{scenario_path}: expected non-empty string for {field_name}")
    return value


def require_optional_string(value: Any, *, field_name: str, scenario_path: Path) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{scenario_path}: expected a non-empty string for {field_name} when present")
    return value


def require_string_list(value: Any, *, field_name: str, scenario_path: Path) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScenarioError(f"{scenario_path}: expected a string list for {field_name}")
    return list(value)


def require_optional_string_list(value: Any, *, field_name: str, scenario_path: Path) -> list[str]:
    if value is None:
        return []
    return require_string_list(value, field_name=field_name, scenario_path=scenario_path)


def require_nonnegative_float(value: Any, *, field_name: str, scenario_path: Path) -> float:
    if not isinstance(value, (int, float)):
        raise ScenarioError(f"{scenario_path}: expected a number for {field_name}")
    if value < 0:
        raise ScenarioError(f"{scenario_path}: expected a non-negative number for {field_name}")
    return float(value)


def require_optional_bool(value: Any, *, field_name: str, scenario_path: Path) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ScenarioError(f"{scenario_path}: expected a JSON boolean for {field_name}")
    return value


def format_field_names(fields: list[str] | frozenset[str]) -> str:
    return ", ".join(repr(field) for field in sorted(fields))


def require_object(value: Any, *, field_name: str, object_path: Path) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScenarioError(f"{object_path}: expected {field_name} to be an object")
    return dict(value)


def reject_unsupported_fields(
    raw: dict[str, Any],
    *,
    allowed_fields: frozenset[str],
    context: str,
    scenario_path: Path,
) -> None:
    unsupported = sorted(set(raw) - allowed_fields)
    if not unsupported:
        return
    raise ScenarioError(
        f"{scenario_path}, {context} has unsupported field(s): {unsupported}. "
        f"This runner currently accepts only the composition fields {format_field_names(allowed_fields)}."
    )


def role_context_key(role_name: str, field_name: str) -> str:
    def normalize(value: str) -> str:
        cleaned = "".join(char if char.isalnum() else "_" for char in value).strip("_").upper()
        return cleaned or "VALUE"

    return f"ROLE_{normalize(role_name)}_{normalize(field_name)}"


def service_context_key(service_name: str, field_name: str) -> str:
    service_part = slugify(service_name).replace("-", "_").upper()
    if not field_name:
        return f"SERVICE_{service_part}_"
    return f"SERVICE_{service_part}_{slugify(field_name).replace('-', '_').upper()}"


def fixture_context_key(fixture_name: str, field_name: str) -> str:
    fixture_part = slugify(fixture_name).replace("-", "_").upper()
    if not field_name:
        return f"FIXTURE_{fixture_part}_"
    return f"FIXTURE_{fixture_part}_{slugify(field_name).replace('-', '_').upper()}"


def probe_context_key(step_name: str, field_name: str) -> str:
    probe_part = slugify(step_name).replace("-", "_").upper()
    if not field_name:
        return f"PROBE_{probe_part}_"
    return f"PROBE_{probe_part}_{slugify(field_name).replace('-', '_').upper()}"


def ensure_role_exists(role_name: str, *, topology: TopologySpec, object_path: Path, field_name: str) -> str:
    if role_name not in topology.roles:
        raise ScenarioError(
            f"{object_path}: {field_name} references unknown topology role {role_name!r} for topology {topology.name!r}"
        )
    return role_name


def resolve_text(template: str, context: dict[str, str], *, scenario_name: str) -> str:
    try:
        return template.format_map(context)
    except KeyError as exc:
        missing = exc.args[0]
        raise ScenarioError(
            f"Scenario {scenario_name!r} references unknown placeholder {missing!r} in {template!r}"
        ) from exc


def resolve_value(value: Any, context: dict[str, str], *, scenario_name: str) -> Any:
    if isinstance(value, str):
        return resolve_text(value, context, scenario_name=scenario_name)
    if isinstance(value, list):
        return [resolve_value(item, context, scenario_name=scenario_name) for item in value]
    if isinstance(value, dict):
        return {key: resolve_value(item, context, scenario_name=scenario_name) for key, item in value.items()}
    return value


def context_set_scalar(context: dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        context[key] = "1" if value else "0"
    else:
        context[key] = str(value)


def update_context_from_outputs(context: dict[str, str], prefix_key: str, outputs: dict[str, Any]) -> None:
    for key, value in outputs.items():
        normalized_key = slugify(str(key)).replace("-", "_").upper()
        context_set_scalar(context, prefix_key + normalized_key, value)


def fixture_record_payload(
    fixture: FixtureSpec,
    outputs: dict[str, Any],
    artifacts: dict[str, str],
    options: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": fixture.name,
        "kind": fixture.kind,
        "description": fixture.description,
        "options": options,
        "outputs": outputs,
        "artifacts": artifacts,
    }


def parse_service(raw: Any, *, scenario_path: Path, topology: TopologySpec) -> ServiceSpec:
    if not isinstance(raw, dict):
        raise ScenarioError(f"{scenario_path}: services entries must be objects")
    service_context = f"service {raw['name']!r}" if isinstance(raw.get("name"), str) and raw.get("name") else "services[] entry"
    reject_unsupported_fields(
        raw,
        allowed_fields=SERVICE_FIELDS,
        context=service_context,
        scenario_path=scenario_path,
    )
    kind = require_string(raw.get("kind"), field_name="services[].kind", scenario_path=scenario_path)
    if kind not in {"dsh-listener"}:
        raise ScenarioError(f"{scenario_path}: unsupported service kind {kind!r}")
    role = ensure_role_exists(
        require_string(raw.get("role"), field_name="services[].role", scenario_path=scenario_path),
        topology=topology,
        object_path=scenario_path,
        field_name="services[].role",
    )
    return ServiceSpec(
        name=require_string(raw.get("name"), field_name="services[].name", scenario_path=scenario_path),
        kind=kind,
        role=role,
        wait_s=require_nonnegative_float(raw.get("wait_s", 0.0), field_name="services[].wait_s", scenario_path=scenario_path),
        bootstrap_fixture=require_optional_string(
            raw.get("bootstrap_fixture"),
            field_name="services[].bootstrap_fixture",
            scenario_path=scenario_path,
        ),
    )


def parse_step(raw: Any, *, scenario_path: Path) -> StepSpec:
    if not isinstance(raw, dict):
        raise ScenarioError(f"{scenario_path}: steps must contain objects")
    step_context = f"step {raw['name']!r}" if isinstance(raw.get("name"), str) and raw.get("name") else "steps[] entry"
    reject_unsupported_fields(
        raw,
        allowed_fields=PROBE_STEP_FIELDS,
        context=step_context,
        scenario_path=scenario_path,
    )
    name = require_string(raw.get("name"), field_name="steps[].name", scenario_path=scenario_path)
    probe_name = require_string(raw.get("probe"), field_name="steps[].probe", scenario_path=scenario_path)
    inputs = require_object(raw.get("inputs"), field_name="steps[].inputs", object_path=scenario_path)
    return StepSpec(
        name=name,
        inputs=inputs,
        allow_failure=require_optional_bool(
            raw.get("allow_failure"),
            field_name="steps[].allow_failure",
            scenario_path=scenario_path,
        ),
        probe=probe_name,
    )
