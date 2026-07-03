from __future__ import annotations

from pathlib import Path
from typing import Any

from .fixture_command_core import require_object, run_fixture_command
from .lifecycle import copy_named_artifacts
from lib.core.models import FixtureSpec, ScenarioError
from lib.reporting.result_recorder import ResultRecorder
from lib.core.util import slugify


def stop_fixture(
    recorder: ResultRecorder,
    fixture_payload: dict[str, Any],
    *,
    capture_suffix: str = "down",
) -> tuple[str, str]:
    fixture_name = str(fixture_payload["name"])
    runtime = fixture_payload.get("options", {})
    if not isinstance(runtime, dict):
        return "passed", f"Fixture {fixture_name} has no runtime data to stop."
    stop_command = runtime.get("stop")
    if stop_command is None:
        return "passed", f"Fixture {fixture_name} has no stop command."
    outputs = fixture_payload.get("outputs", {})
    artifacts = fixture_payload.get("artifacts", {})
    if not isinstance(outputs, dict) or not isinstance(artifacts, dict):
        return "failed", f"Fixture {fixture_name} has invalid stop context."

    command = require_object(
        stop_command,
        field_name="fixture.runtime.stop",
        object_path=Path(str(fixture_payload.get("path", "<fixture>"))),
    )
    stop_context = {
        **outputs,
        **artifacts,
        "name": fixture_name,
        "fixture_name": fixture_name,
        "kind": str(fixture_payload.get("kind", "")),
    }
    runtime_env = {
        "VNET_FIXTURE_NAME": fixture_name,
        "VNET_FIXTURE_KIND": str(fixture_payload.get("kind", "")),
        "VNET_FIXTURE_ROLE": str(outputs.get("role", "")),
        "VNET_FIXTURE_NAMESPACE": str(outputs.get("namespace", "")),
    }
    try:
        run_fixture_command(
            recorder,
            fixture=FixtureSpec(
                name=fixture_name,
                kind=str(fixture_payload.get("kind", "")),
                description="",
                options=runtime,
            ),
            phase="stop",
            command=command,
            runtime_env=runtime_env,
            command_context=stop_context,
            capture_name=f"fixtures/{slugify(fixture_name)}-{capture_suffix}.txt",
        )
    except ScenarioError as exc:
        return "failed", str(exc)
    return "passed", f"Fixture {fixture_name} stop command completed."


def copy_fixture_artifacts(recorder: ResultRecorder, fixture_payloads: dict[str, dict[str, Any]]) -> None:
    for fixture_name, payload in sorted(fixture_payloads.items()):
        artifacts = payload.get("artifacts", {})
        if isinstance(artifacts, dict):
            copied_artifacts = {
                str(key): str(value)
                for key, value in artifacts.items()
                if str(key) != "pidfile"
            }
            copy_named_artifacts(
                recorder,
                artifacts=copied_artifacts,
                prefix=f"fixtures/{slugify(fixture_name)}",
                label_prefix=f"Fixture artifact ({fixture_name})",
            )
