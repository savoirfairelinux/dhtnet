from __future__ import annotations

from typing import Any

from lib.loaders.context_loader import (
    fixture_context_key,
    fixture_record_payload,
    require_string,
    resolve_value,
    update_context_from_outputs,
)
from .fixture_command_core import (
    command_context,
    command_role_namespace,
    require_object,
    require_optional_object,
)
from .fixture_command_core import resolved_string_dict, run_fixture_command
from .fixture_command_teardown import copy_fixture_artifacts, stop_fixture
from lib.core.models import FixtureSpec, ScenarioError, ScenarioSpec, TopologySpec
from lib.reporting.result_recorder import ResultRecorder, RunState
from lib.core.util import slugify


def publish_context_values(
    context: dict[str, str],
    publish: dict[str, Any],
    command_context: dict[str, Any],
    *,
    fixture: FixtureSpec,
    scenario: ScenarioSpec,
) -> None:
    resolved = resolve_value(publish, command_context, scenario_name=scenario.name)
    if not isinstance(resolved, dict):
        raise ScenarioError(f"{fixture.path or scenario.path}: fixture.runtime.publish must resolve to an object")
    for key, value in resolved.items():
        if not isinstance(key, str) or not key:
            raise ScenarioError(f"{fixture.path or scenario.path}: fixture.runtime.publish keys must be strings")
        string_value = str(value)
        previous_value = context.get(key)
        if previous_value is not None and previous_value != string_value:
            raise ScenarioError(
                f"Fixture {fixture.name!r} publishes conflicting value for context key {key}."
            )
        context[key] = string_value


def resolved_runtime_payload(
    runtime: dict[str, Any],
    stop_context: dict[str, Any],
    *,
    scenario: ScenarioSpec,
) -> dict[str, Any]:
    runtime_payload = dict(runtime)
    if runtime.get("stop") is not None:
        runtime_payload["stop"] = resolve_value(
            runtime["stop"],
            stop_context,
            scenario_name=scenario.name,
        )
    return runtime_payload


def resolved_artifacts(
    runtime: dict[str, Any],
    artifact_context: dict[str, Any],
    *,
    fixture: FixtureSpec,
    scenario: ScenarioSpec,
) -> dict[str, str]:
    object_path = fixture.path or scenario.path
    raw_artifacts = require_optional_object(
        runtime.get("artifacts"),
        field_name="fixture.runtime.artifacts",
        object_path=object_path,
    )
    artifacts = resolve_value(raw_artifacts, artifact_context, scenario_name=scenario.name)
    if not isinstance(artifacts, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in artifacts.items()
    ):
        raise ScenarioError(f"{object_path}: fixture.runtime.artifacts must resolve to a string map")
    return dict(artifacts)


def setup_fixture(
    recorder: ResultRecorder,
    fixture: FixtureSpec,
    *,
    scenario: ScenarioSpec,
    topology: TopologySpec,
    context: dict[str, str],
    run_state: RunState,
) -> dict[str, Any]:
    object_path = fixture.path or scenario.path
    runtime = require_object(fixture.options, field_name="fixture.runtime", object_path=object_path)
    runtime_kind = require_string(
        runtime.get("kind"),
        field_name="fixture.runtime.kind",
        scenario_path=object_path,
    )
    if runtime_kind != "command":
        raise ScenarioError(f"{object_path}: unsupported fixture runtime kind {runtime_kind!r}")

    role_name, namespace = command_role_namespace(
        runtime,
        default_role="",
        topology=topology,
        context=context,
        scenario=scenario,
        fixture=fixture,
    )
    outputs: dict[str, Any] = {"role": role_name, "namespace": namespace}
    artifacts: dict[str, str] = {}
    base_command_context = command_context(
        context,
        fixture=fixture,
        role_name=role_name,
        namespace=namespace,
        outputs=outputs,
        artifacts=artifacts,
    )
    runtime_env = {
        "VNET_FIXTURE_NAME": fixture.name,
        "VNET_FIXTURE_KIND": fixture.kind,
        "VNET_FIXTURE_ROLE": role_name,
        "VNET_FIXTURE_NAMESPACE": namespace,
    }
    runtime_env.update(
        resolved_string_dict(
            runtime.get("env"),
            base_command_context,
            field_name="fixture.runtime.env",
            scenario_name=scenario.name,
            object_path=object_path,
        )
    )

    started = False
    runtime_payload: dict[str, Any] | None = None

    def mark_started() -> None:
        nonlocal started
        started = True

    try:
        start_outputs = run_fixture_command(
            recorder,
            fixture=fixture,
            phase="start",
            command=require_object(runtime.get("start"), field_name="fixture.runtime.start", object_path=object_path),
            runtime_env=runtime_env,
            command_context=base_command_context,
            capture_name=f"fixtures/{slugify(fixture.name)}-up.txt",
            on_success=mark_started,
        )
        outputs.update(start_outputs)

        ready_command = runtime.get("ready")
        if ready_command is not None:
            ready = require_object(ready_command, field_name="fixture.runtime.ready", object_path=object_path)
            ready_role, ready_namespace = command_role_namespace(
                ready,
                default_role=role_name,
                topology=topology,
                context=context,
                scenario=scenario,
                fixture=fixture,
            )
            ready_context = command_context(
                context,
                fixture=fixture,
                role_name=ready_role,
                namespace=ready_namespace,
                outputs=outputs,
                artifacts=artifacts,
            )
            ready_env = dict(runtime_env)
            ready_env["VNET_FIXTURE_ROLE"] = ready_role
            ready_env["VNET_FIXTURE_NAMESPACE"] = ready_namespace
            ready_outputs = run_fixture_command(
                recorder,
                fixture=fixture,
                phase="ready",
                command=ready,
                runtime_env=ready_env,
                command_context=ready_context,
                capture_name=f"fixtures/{slugify(fixture.name)}-ready.txt",
            )
            outputs.update(ready_outputs)

        artifact_context = command_context(
            context,
            fixture=fixture,
            role_name=role_name,
            namespace=namespace,
            outputs=outputs,
            artifacts=artifacts,
        )
        artifact_context.update(runtime_env)
        artifacts.update(
            resolved_artifacts(
                runtime,
                artifact_context,
                fixture=fixture,
                scenario=scenario,
            )
        )

        publish = require_optional_object(
            runtime.get("publish"),
            field_name="fixture.runtime.publish",
            object_path=object_path,
        )
        if publish:
            publish_context_values(
                context,
                publish,
                command_context(
                    context,
                    fixture=fixture,
                    role_name=role_name,
                    namespace=namespace,
                    outputs=outputs,
                    artifacts=artifacts,
                ),
                fixture=fixture,
                scenario=scenario,
            )

        stop_context = command_context(
            context,
            fixture=fixture,
            role_name=role_name,
            namespace=namespace,
            outputs=outputs,
            artifacts=artifacts,
        )
        stop_context.update(runtime_env)
        runtime_payload = resolved_runtime_payload(
            runtime,
            stop_context,
            scenario=scenario,
        )
    except ScenarioError:
        if started:
            try:
                cleanup_stop_context = command_context(
                    context,
                    fixture=fixture,
                    role_name=role_name,
                    namespace=namespace,
                    outputs=outputs,
                    artifacts=artifacts,
                )
                cleanup_stop_context.update(runtime_env)
                cleanup_runtime = resolved_runtime_payload(
                    runtime,
                    cleanup_stop_context,
                    scenario=scenario,
                )
                stop_status, stop_details = stop_fixture(
                    recorder,
                    {
                        "name": fixture.name,
                        "kind": fixture.kind,
                        "outputs": outputs,
                        "artifacts": artifacts,
                        "options": cleanup_runtime,
                    },
                    capture_suffix="down-after-ready-failure",
                )
                recorder.note(
                    f"fixture_start_failure_cleanup:{fixture.name}:"
                    f"status={stop_status}:details={stop_details}"
                )
            except ScenarioError as cleanup_exc:
                recorder.note(
                    f"fixture_start_failure_cleanup:{fixture.name}:"
                    f"failed={cleanup_exc}"
                )
        try:
            failure_artifact_context = command_context(
                context,
                fixture=fixture,
                role_name=role_name,
                namespace=namespace,
                outputs=outputs,
                artifacts=artifacts,
            )
            failure_artifact_context.update(runtime_env)
            artifacts.update(
                resolved_artifacts(
                    runtime,
                    failure_artifact_context,
                    fixture=fixture,
                    scenario=scenario,
                )
            )
            copy_fixture_artifacts(
                recorder,
                {
                    fixture.name: {
                        "artifacts": artifacts,
                    },
                },
            )
        except ScenarioError as artifact_exc:
            recorder.note(
                f"fixture_failure_artifacts:{fixture.name}:"
                f"failed={artifact_exc}"
            )
        raise

    if runtime_payload is None:
        raise ScenarioError(f"Fixture {fixture.name!r} did not produce runtime payload.")
    payload = fixture_record_payload(fixture, outputs, artifacts, runtime_payload)
    run_state.set_fixture(fixture.name, payload)
    update_context_from_outputs(context, fixture_context_key(fixture.name, ""), outputs)
    return payload
