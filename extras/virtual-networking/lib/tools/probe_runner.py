from __future__ import annotations

import os
import re
import signal
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TextIO

from lib.core.models import ProbeSpec, ScenarioError
from lib.core.util import now_ms
from lib.reporting.result_recorder import ResultRecorder, initialize_result_layout

EXACT_PLACEHOLDER_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")


@dataclass
class ManagedProcess:
    process: subprocess.Popen[str]
    log_handle: TextIO


@dataclass
class ProbeSequenceState:
    probe: ProbeSpec
    inputs: dict[str, Any]
    context: dict[str, str]
    recorder: ResultRecorder
    outputs: dict[str, Any] = field(default_factory=dict)
    processes: list[ManagedProcess] = field(default_factory=list)
    temp_dirs: list[Path] = field(default_factory=list)

    def lookup(self, key: str) -> Any:
        if key in self.outputs:
            return self.outputs[key]
        if key in self.inputs:
            return self.inputs[key]
        if key in self.context:
            return self.context[key]
        raise ScenarioError(f"Probe {self.probe.name!r} references unknown value {key!r}")

    def optional_input(self, key: str) -> Any:
        value = self.inputs.get(key)
        if value is None or value == "":
            return None
        return value


@dataclass(frozen=True)
class ActionOutcome:
    success: bool = True
    details: str = ""


@dataclass(frozen=True)
class ProbeSequenceResult:
    status: str
    details: str
    outputs: dict[str, Any]


@dataclass(frozen=True)
class ActionSchema:
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


ActionHandler = Callable[[dict[str, Any], ProbeSequenceState], ActionOutcome]

COMMON_ACTION_FIELDS = frozenset({"id", "type"})
ACTION_SCHEMAS: dict[str, ActionSchema] = {}
ACTION_HANDLERS: dict[str, ActionHandler] = {}


def register_probe_action(kind: str, schema: ActionSchema, handler: ActionHandler) -> None:
    if not kind:
        raise ScenarioError("Probe action registrations require a non-empty action type")
    if kind in ACTION_SCHEMAS:
        raise ScenarioError(f"Probe action type {kind!r} is already registered")
    ACTION_SCHEMAS[kind] = schema
    ACTION_HANDLERS[kind] = handler


def format_fields(fields: frozenset[str] | set[str]) -> str:
    return ", ".join(repr(field) for field in sorted(fields))


def validate_probe_action(action: dict[str, Any], *, probe_name: str, path: Path | None = None, index: int | None = None) -> None:
    location = f"Probe {probe_name!r}"
    if path is not None:
        location = f"{path}: probe {probe_name!r}"
    if index is not None:
        location = f"{location} action[{index}]"

    kind = action.get("type")
    if not isinstance(kind, str) or not kind:
        raise ScenarioError(f"{location} requires non-empty string action field 'type'")
    if "id" in action and (not isinstance(action["id"], str) or not action["id"]):
        raise ScenarioError(f"{location} requires non-empty string action field 'id' when present")

    schema = ACTION_SCHEMAS.get(kind)
    if schema is None:
        raise ScenarioError(
            f"{location} has unsupported action type {kind!r}. "
            f"Supported action types: {format_fields(set(ACTION_SCHEMAS))}"
        )

    missing = schema.required - set(action)
    if missing:
        raise ScenarioError(f"{location} ({kind}) is missing required field(s): {format_fields(missing)}")

    allowed = COMMON_ACTION_FIELDS | schema.required | schema.optional
    unsupported = set(action) - allowed
    if unsupported:
        raise ScenarioError(
            f"{location} ({kind}) has unsupported field(s): {format_fields(unsupported)}. "
            f"Allowed fields: {format_fields(allowed)}"
        )


class TemplateValues(dict[str, Any]):
    def __init__(self, state: ProbeSequenceState) -> None:
        super().__init__()
        self.state = state

    def __missing__(self, key: str) -> str:
        value = self.state.lookup(key)
        return str(value)


def resolve_text(value: str, state: ProbeSequenceState) -> str:
    try:
        return value.format_map(TemplateValues(state))
    except KeyError as exc:
        missing = exc.args[0]
        raise ScenarioError(f"Probe {state.probe.name!r} references unknown placeholder {missing!r}") from exc


def resolve_value(value: Any, state: ProbeSequenceState) -> Any:
    if isinstance(value, str):
        return resolve_text(value, state)
    if isinstance(value, list):
        return [resolve_value(item, state) for item in value]
    if isinstance(value, dict):
        return {key: resolve_value(item, state) for key, item in value.items()}
    return value


def resolve_action_value(value: Any, state: ProbeSequenceState) -> Any:
    if isinstance(value, str):
        placeholder_match = EXACT_PLACEHOLDER_RE.match(value)
        if placeholder_match:
            return state.lookup(placeholder_match.group(1))
    return resolve_value(value, state)


def require_string(value: Any, *, field_name: str, state: ProbeSequenceState) -> str:
    resolved = resolve_value(value, state)
    if not isinstance(resolved, str) or not resolved:
        raise ScenarioError(f"Probe {state.probe.name!r} requires non-empty string field {field_name}")
    return resolved


def optional_string(action: dict[str, Any], key: str, state: ProbeSequenceState, default: str = "") -> str:
    if key not in action:
        return default
    return require_string(action[key], field_name=key, state=state)


def require_string_list(value: Any, *, field_name: str, state: ProbeSequenceState) -> list[str]:
    resolved = resolve_value(value, state)
    if not isinstance(resolved, list) or not all(isinstance(item, str) and item for item in resolved):
        raise ScenarioError(f"Probe {state.probe.name!r} requires string-list field {field_name}")
    return list(resolved)


def materialize_argv(argv_template: Any, state: ProbeSequenceState, *, field_name: str) -> list[str]:
    if not isinstance(argv_template, list) or not all(isinstance(item, str) for item in argv_template):
        raise ScenarioError(f"Probe {state.probe.name!r} requires string-list field {field_name}")

    materialized: list[str] = []
    for item in argv_template:
        placeholder_match = EXACT_PLACEHOLDER_RE.match(item)
        if placeholder_match:
            value = state.lookup(placeholder_match.group(1))
            if isinstance(value, list):
                materialized.extend(str(part) for part in value)
            elif value is None:
                continue
            elif isinstance(value, dict):
                raise ScenarioError(
                    f"Probe {state.probe.name!r} cannot expand object value {placeholder_match.group(1)!r} into argv"
                )
            else:
                materialized.append(str(value))
            continue
        materialized.append(resolve_text(item, state))
    return materialized


def action_id(action: dict[str, Any]) -> str:
    value = action.get("id") or action.get("type")
    if not isinstance(value, str) or not value:
        raise ScenarioError("Probe-sequence action is missing non-empty id/type")
    return value


def action_type(action: dict[str, Any]) -> str:
    value = action.get("type")
    if not isinstance(value, str) or not value:
        raise ScenarioError("Probe-sequence action is missing non-empty type")
    return value


def action_timeout_s(action: dict[str, Any], default: float) -> float:
    return action_number(action, "timeout_s", default)


def action_number(action: dict[str, Any], key: str, default: float) -> float:
    value = action.get(key, default)
    if not isinstance(value, (int, float)) or value < 0:
        raise ScenarioError(f"Action {action_id(action)!r} requires non-negative numeric {key}")
    return float(value)


def capture_path(recorder: ResultRecorder, destination: str) -> Path:
    return recorder.command_capture_path(destination)


def capture_reference(recorder: ResultRecorder, path: Path) -> str:
    return recorder.capture_reference(path)


def record_assertion(
    recorder: ResultRecorder,
    name: str,
    status: str,
    started_ms: int,
    details: str,
) -> None:
    recorder.assertion(name, status, now_ms() - started_ms, details)


def run_action(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    kind = action_type(action)
    handler = ACTION_HANDLERS.get(kind)
    if handler is None:
        raise ScenarioError(f"Probe {state.probe.name!r} has unsupported probe_sequence action type {kind!r}")
    name = action_id(action)
    validate_probe_action(action, probe_name=state.probe.name)
    state.recorder.event("probe_action_started", "info", f"{name}: {kind}")
    outcome = handler(action, state)
    state.recorder.event(
        "probe_action_finished",
        "passed" if outcome.success else "failed",
        f"{name}: {kind}. {outcome.details}".strip(),
    )
    return outcome


def cleanup_state(state: ProbeSequenceState) -> None:
    for managed in reversed(state.processes):
        process = managed.process
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        managed.log_handle.close()

    for temp_dir in reversed(state.temp_dirs):
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_probe_sequence(
    probe: ProbeSpec,
    *,
    inputs: dict[str, Any],
    context: dict[str, str],
    result_dir: Path,
    artifact_root: Path,
    run_id: str,
) -> ProbeSequenceResult:
    layout = initialize_result_layout(
        run_id=run_id,
        scenario=probe.name,
        artifact_root=artifact_root,
        run_dir=result_dir,
        captures_dir=result_dir,
        write_events=False,
    )
    recorder = ResultRecorder.from_layout(layout)
    state = ProbeSequenceState(probe=probe, inputs=inputs, context=context, recorder=recorder)
    status = "passed"
    details = "Probe sequence passed."

    recorder.event("run_started", "info", f"Probe {probe.name!r} started")
    for key in ("topology",):
        value = inputs.get(key)
        if value not in (None, ""):
            recorder.field(key, value)

    try:
        for action in probe.probe_sequence:
            outcome = run_action(action, state)
            if not outcome.success:
                status = "failed"
                details = outcome.details
                break
    except ScenarioError as exc:
        status = "error"
        details = str(exc)
        recorder.event("probe_error", "error", str(exc))
        recorder.note(f"probe_error={exc}")
    except Exception as exc:
        status = "error"
        details = str(exc)
        recorder.event("probe_error", "error", str(exc))
        recorder.note(f"probe_error={exc}")
        raise
    finally:
        cleanup_state(state)
        recorder.event("run_finished", status, f"Probe finished with status {status}")

    return ProbeSequenceResult(
        status=status,
        details=details,
        outputs=dict(state.outputs),
    )
