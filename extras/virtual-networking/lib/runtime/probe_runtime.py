from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from lib.tools.probe_actions import register_default_probe_actions
from lib.tools.probe_runner import run_probe_sequence
from lib.loaders.context_loader import (
    actor_context_key,
    fixture_context_key,
    probe_context_key,
    require_string,
    resolve_text,
    role_context_key,
    update_context_from_outputs,
)
from lib.core.models import ProbeSpec, ScenarioError, ScenarioSpec, StepSpec
from lib.reporting.result_recorder import ResultRecorder, RunState
from lib.core.util import now_ms, slugify

register_default_probe_actions()


def register_probe_outputs(context: dict[str, str], step_name: str, payload: dict[str, Any]) -> None:
    propagated: dict[str, Any] = {
        "status": payload.get("status", ""),
        "result_dir": payload.get("result_dir", ""),
    }
    outputs = payload.get("outputs", {})
    if isinstance(outputs, dict):
        propagated.update(outputs)
    update_context_from_outputs(context, probe_context_key(step_name, ""), propagated)


def build_probe_local_context(
    recorder: ResultRecorder,
    step: StepSpec,
    context: dict[str, str],
) -> tuple[dict[str, str], Path]:
    probe_slug = slugify(step.name)
    probe_run_id = f"{context['run_id']}-{probe_slug}"
    probe_result_dir = recorder.captures_dir / "probes" / probe_slug
    local_context = dict(context)
    local_context["probe_run_id"] = probe_run_id
    local_context["PROBE_RUN_ID"] = probe_run_id
    local_context["probe_result_dir"] = str(probe_result_dir)
    local_context["PROBE_RESULT_DIR"] = str(probe_result_dir)
    return local_context, probe_result_dir


def resolve_probe_binding(
    binding: Any,
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
    binding_path: str,
) -> Any:
    if isinstance(binding, str):
        return resolve_text(binding, context, scenario_name=scenario.name)
    if isinstance(binding, list):
        return [
            resolve_probe_binding(item, context=context, scenario=scenario, binding_path=f"{binding_path}[{index}]")
            for index, item in enumerate(binding)
        ]
    if not isinstance(binding, dict):
        return binding

    source_keys = [key for key in ("role", "actor", "fixture", "context", "value") if key in binding]
    if len(source_keys) > 1:
        raise ScenarioError(
            f"Scenario {scenario.name!r} binding {binding_path!r} must reference exactly one source, got {source_keys}"
        )
    if "value" in binding:
        return resolve_probe_binding(binding["value"], context=context, scenario=scenario, binding_path=f"{binding_path}.value")
    if "role" in binding:
        role_name = require_string(binding["role"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field", "namespace")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding a role")
        context_key = role_context_key(role_name, field_name)
    elif "actor" in binding:
        actor_name = require_string(binding["actor"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field", "namespace")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding an actor")
        context_key = actor_context_key(actor_name, field_name)
    elif "fixture" in binding:
        fixture_name = require_string(binding["fixture"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding a fixture")
        context_key = fixture_context_key(fixture_name, field_name)
    elif "context" in binding:
        context_key = require_string(binding["context"], field_name=binding_path, scenario_path=scenario.path)
    else:
        return {
            key: resolve_probe_binding(value, context=context, scenario=scenario, binding_path=f"{binding_path}.{key}")
            for key, value in binding.items()
        }

    if context_key not in context:
        raise ScenarioError(
            f"Scenario {scenario.name!r} binding {binding_path!r} references unavailable context key {context_key!r}"
        )
    return context[context_key]


def resolve_probe_inputs(step: StepSpec, context: dict[str, str], *, scenario: ScenarioSpec) -> dict[str, Any]:
    return {
        input_name: resolve_probe_binding(binding, context=context, scenario=scenario, binding_path=f"step {step.name}.inputs.{input_name}")
        for input_name, binding in step.inputs.items()
    }


def build_default_probe_inputs(
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
) -> dict[str, Any]:
    return {
        "run_id": context["probe_run_id"],
        "result_dir": context["probe_result_dir"],
        "artifact_root": context["artifact_root"],
        "topology": scenario.topology,
        "scenario": scenario.name,
    }


def add_scalar_probe_inputs_to_context(context: dict[str, str], inputs: dict[str, Any]) -> dict[str, str]:
    merged = dict(context)
    for key, value in inputs.items():
        if value is None:
            continue
        if isinstance(value, bool):
            merged[key] = "1" if value else "0"
        elif isinstance(value, (str, int, float)):
            merged[key] = str(value)
    return merged


def record_skipped_steps(
    recorder: ResultRecorder,
    steps: Sequence[StepSpec],
    *,
    reason: str,
) -> None:
    for step in steps:
        recorder.assertion(step.name, "skipped", 0, reason)
        recorder.event("step_skipped", "skipped", f"{step.name}: {reason}")


def execute_probe_sequence_step(
    recorder: ResultRecorder,
    step: StepSpec,
    probe: ProbeSpec,
    inputs: dict[str, Any],
    context: dict[str, str],
    probe_result_dir: Path,
) -> tuple[bool, str, dict[str, Any]]:
    started_ms = now_ms()
    recorder.event("step_started", "info", f"{step.name}: probe_sequence probe {probe.name}")
    result = run_probe_sequence(
        probe,
        inputs=inputs,
        context=context,
        result_dir=probe_result_dir,
        artifact_root=Path(context["artifact_root"]),
        run_id=str(inputs["run_id"]),
    )

    details = [
        f"Probe sequence finished with status {result.status}.",
    ]
    if result.details:
        details.append(result.details)
    if result.status != "passed":
        status = "failed"
        success = step.allow_failure
    else:
        status = "passed"
        success = True

    recorder.assertion(step.name, status, now_ms() - started_ms, " ".join(details))
    recorder.event("step_finished", status, f"{step.name}: sequence_status={result.status}")
    return success, status, result.outputs


def execute_probe_step(
    recorder: ResultRecorder,
    step: StepSpec,
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
    probes: dict[str, ProbeSpec],
    run_state: RunState,
) -> bool:
    if step.probe is None:
        raise ScenarioError(f"Scenario {scenario.name!r} step {step.name!r} is missing a probe name")
    probe = probes.get(step.probe)
    if probe is None:
        raise ScenarioError(f"Scenario {scenario.name!r} step {step.name!r} references unknown probe {step.probe!r}")

    local_context, probe_result_dir = build_probe_local_context(recorder, step, context)
    resolved_inputs = resolve_probe_inputs(step, local_context, scenario=scenario)
    probe_inputs = {**build_default_probe_inputs(local_context, scenario=scenario), **resolved_inputs}

    missing_inputs = [
        input_name
        for input_name in probe.required_inputs
        if input_name not in probe_inputs or probe_inputs[input_name] is None or probe_inputs[input_name] == ""
    ]
    if missing_inputs:
        raise ScenarioError(
            f"Scenario {scenario.name!r} step {step.name!r} is missing required probe inputs for {probe.name!r}: {', '.join(missing_inputs)}"
        )

    command_context = add_scalar_probe_inputs_to_context(local_context, probe_inputs)
    success, status, result_outputs = execute_probe_sequence_step(
        recorder,
        step,
        probe,
        probe_inputs,
        command_context,
        probe_result_dir,
    )

    probe_payload = {
        "name": step.name,
        "probe": probe.name,
        "status": status,
        "result_dir": str(probe_result_dir),
        "inputs": probe_inputs,
        "outputs": result_outputs,
    }
    run_state.set_probe(step.name, probe_payload)
    register_probe_outputs(context, step.name, probe_payload)
    return success
