from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from lib.loaders.context_loader import (
    ensure_role_exists,
    require_string,
    resolve_value,
    role_context_key,
)
from .lifecycle import run_command
from lib.core.models import FixtureSpec, ScenarioError, ScenarioSpec, TopologySpec
from lib.reporting.result_recorder import ResultRecorder
from lib.core.util import slugify


def fixture_output_path(fixture_name: str, phase: str) -> Path:
    fixture_slug = slugify(fixture_name)
    return Path(tempfile.gettempdir()) / (
        f"vnet-fixture-output-{fixture_slug}-{phase}-{os.getpid()}-"
        f"{int(time.time() * 1000)}.json"
    )


def require_object(value: Any, *, field_name: str, object_path: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{object_path}: expected {field_name} to be an object")
    return dict(value)


def require_optional_object(value: Any, *, field_name: str, object_path: Path) -> dict[str, Any]:
    if value is None:
        return {}
    return require_object(value, field_name=field_name, object_path=object_path)


def require_string_list(value: Any, *, field_name: str, object_path: Path) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ScenarioError(f"{object_path}: expected {field_name} to be a non-empty string list")
    return list(value)


def resolved_string_dict(
    value: Any,
    command_context: dict[str, Any],
    *,
    field_name: str,
    scenario_name: str,
    object_path: Path,
) -> dict[str, str]:
    raw = require_optional_object(value, field_name=field_name, object_path=object_path)
    resolved = resolve_value(raw, command_context, scenario_name=scenario_name)
    if not isinstance(resolved, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in resolved.items()
    ):
        raise ScenarioError(f"{object_path}: expected {field_name} to resolve to a string map")
    return dict(resolved)


class OptionalContext(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return ""


def resolved_optional_string_dict(
    value: Any,
    command_context: dict[str, Any],
    *,
    field_name: str,
    object_path: Path,
) -> dict[str, str]:
    raw = require_optional_object(value, field_name=field_name, object_path=object_path)
    resolved: dict[str, str] = {}
    for key, item in raw.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ScenarioError(f"{object_path}: expected {field_name} to be a string map")
        rendered = item.format_map(OptionalContext(command_context))
        if rendered:
            resolved[key] = rendered
    return resolved


def read_json_output(output_path: Path, *, fixture_name: str, phase: str) -> dict[str, Any]:
    if not output_path.exists():
        raise ScenarioError(
            f"Fixture {fixture_name!r} {phase} command did not write JSON outputs."
        )
    payload = output_path.read_text(encoding="utf-8")
    if not payload.strip():
        raise ScenarioError(
            f"Fixture {fixture_name!r} {phase} command wrote empty JSON outputs."
        )
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ScenarioError(
            f"Fixture {fixture_name!r} {phase} output file is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ScenarioError(f"Fixture {fixture_name!r} {phase} output must be a JSON object")
    return dict(data)


def required_outputs(command: dict[str, Any], *, object_path: Path) -> tuple[str, ...]:
    raw_outputs = require_optional_object(
        command.get("outputs"),
        field_name="fixture.runtime.command.outputs",
        object_path=object_path,
    )
    if not raw_outputs:
        return ()
    output_type = require_string(
        raw_outputs.get("type"),
        field_name="fixture.runtime.command.outputs.type",
        scenario_path=object_path,
    )
    if output_type != "json":
        raise ScenarioError(f"{object_path}: unsupported fixture output type {output_type!r}")
    required = raw_outputs.get("required", [])
    if not isinstance(required, list) or not all(isinstance(item, str) and item for item in required):
        raise ScenarioError(f"{object_path}: expected fixture outputs.required to be a string list")
    return tuple(required)


def validate_required_outputs(
    outputs: dict[str, Any],
    required: tuple[str, ...],
    *,
    fixture_name: str,
    phase: str,
) -> None:
    missing = [name for name in required if not outputs.get(name)]
    if missing:
        raise ScenarioError(
            f"Fixture {fixture_name!r} {phase} command did not produce required "
            f"output(s): {', '.join(missing)}."
        )


def command_context(
    base_context: dict[str, str],
    *,
    fixture: FixtureSpec,
    role_name: str,
    namespace: str,
    outputs: dict[str, Any],
    artifacts: dict[str, str],
) -> dict[str, Any]:
    return {
        **base_context,
        **outputs,
        **artifacts,
        "name": fixture.name,
        "fixture_name": fixture.name,
        "kind": fixture.kind,
        "role": role_name,
        "namespace": namespace,
    }


def command_role_namespace(
    command: dict[str, Any],
    *,
    default_role: str,
    topology: TopologySpec,
    context: dict[str, str],
    scenario: ScenarioSpec,
    fixture: FixtureSpec,
) -> tuple[str, str]:
    object_path = fixture.path or scenario.path
    raw_role = command.get("role", default_role)
    resolved_role = resolve_value(raw_role, context, scenario_name=scenario.name)
    role_name = ensure_role_exists(
        require_string(
            resolved_role,
            field_name="fixture.runtime.command.role",
            scenario_path=object_path,
        ),
        topology=topology,
        object_path=object_path,
        field_name=f"fixture {fixture.name!r}.runtime.command.role",
    )
    return role_name, context[role_context_key(role_name, "namespace")]


def run_fixture_command(
    recorder: ResultRecorder,
    *,
    fixture: FixtureSpec,
    phase: str,
    command: dict[str, Any],
    runtime_env: dict[str, str],
    command_context: dict[str, Any],
    capture_name: str,
    on_success: Callable[[], None] | None = None,
) -> dict[str, Any]:
    object_path = fixture.path or Path("<fixture>")
    argv = resolve_value(
        require_string_list(
            command.get("argv"),
            field_name=f"fixture.runtime.{phase}.argv",
            object_path=object_path,
        ),
        command_context,
        scenario_name=str(object_path),
    )
    if not isinstance(argv, list) or not all(isinstance(item, str) and item for item in argv):
        raise ScenarioError(f"{object_path}: fixture.runtime.{phase}.argv must resolve to a string list")

    command_env = dict(runtime_env)
    command_env.update(
        resolved_string_dict(
            command.get("env"),
            command_context,
            field_name=f"fixture.runtime.{phase}.env",
            scenario_name=str(object_path),
            object_path=object_path,
        )
    )
    command_env.update(
        resolved_optional_string_dict(
            command.get("optional_env"),
            command_context,
            field_name=f"fixture.runtime.{phase}.optional_env",
            object_path=object_path,
        )
    )

    required = required_outputs(command, object_path=object_path)
    output_path = None
    if required:
        output_path = fixture_output_path(fixture.name, phase)
        command_env["VNET_FIXTURE_OUTPUT_FILE"] = str(output_path)

    capture_path = recorder.command_capture_path(capture_name)
    rc = run_command(argv, capture_path, env=command_env)
    if rc != 0 and not recorder.command_capture_has_output(capture_path):
        with capture_path.open("a", encoding="utf-8") as handle:
            handle.write(f"Command exited {rc} without output.\n")
    capture = recorder.record_command_capture(
        f"Fixture {phase} ({fixture.name})",
        "command-output",
        capture_path,
    )
    if rc != 0:
        details = f"Fixture {fixture.name!r} {phase} command exited {rc}."
        if capture:
            details += f" Capture: {capture}"
        raise ScenarioError(details)
    if on_success is not None:
        on_success()

    if output_path is None:
        return {}
    try:
        outputs = read_json_output(output_path, fixture_name=fixture.name, phase=phase)
    finally:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
    validate_required_outputs(outputs, required, fixture_name=fixture.name, phase=phase)
    return outputs
