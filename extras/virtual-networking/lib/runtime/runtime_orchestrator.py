from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from .service_runtime import service_launch_status, service_status, launch_composition_service, stop_service
from lib.reporting.cli_printer import print_progress
from lib.loaders.context_loader import (
    service_context_key,
    build_scenario_context,
    load_fixtures,
    load_probes,
    resolved_topology_namespaces,
    validate_scenario_against_fixtures,
)
from .fixture_runtime import copy_fixture_artifacts, setup_fixture, stop_fixture
from .lifecycle import apply_tree_ownership, resolve_launch_user
from lib.core.models import ManagedService, ScenarioError, ScenarioSpec
from lib.core.paths import DEFAULT_STATE_ROOT, FIXTURE_DIR, PROBE_DIR, ROOT
from .probe_runtime import execute_probe_step, record_skipped_steps
from lib.reporting.result_recorder import ResultRecorder, RunState
from .topology_runtime import collect_namespace_snapshots, preclean_topology, setup_topology, teardown_topology
from lib.core.util import now_ms, slugify


def run_scenario(
    scenario: ScenarioSpec,
    *,
    artifact_root: Path,
    run_id: str,
    keep_topology: bool,
    service_stop_timeout_s: float,
) -> int:
    if os.geteuid() != 0:
        raise ScenarioError("run requires root privileges")
    if service_stop_timeout_s <= 0:
        raise ScenarioError("--service-stop-timeout-s must be greater than zero")

    artifact_root.mkdir(parents=True, exist_ok=True)
    DEFAULT_STATE_ROOT.mkdir(parents=True, exist_ok=True)
    artifact_owner = resolve_launch_user()
    recorder = ResultRecorder(run_id=run_id, scenario=scenario.name, artifact_root=artifact_root)
    run_state = RunState(recorder.run_state_path, run_id=run_id, scenario=scenario.name)
    topology, context = build_scenario_context(
        scenario,
        artifact_root=artifact_root,
        run_id=run_id,
    )
    fixtures_registry = load_fixtures(FIXTURE_DIR)
    probe_registry = load_probes(PROBE_DIR)
    validate_scenario_against_fixtures(scenario, topology, fixtures_registry, probe_registry)
    context["run_dir"] = str(recorder.run_dir)
    context["RUN_DIR"] = str(recorder.run_dir)
    lab_root = Path(tempfile.mkdtemp(prefix=f"{slugify(scenario.name)}.", dir=str(DEFAULT_STATE_ROOT)))
    context["lab_root"] = str(lab_root)
    context["LAB_ROOT"] = str(lab_root)
    run_state.set_topology(topology)
    run_state.set_context(context)
    status = "passed"
    setup_attempted = False
    should_exit = False
    skip_reason: str | None = None
    next_step_index = 0
    services: dict[str, ManagedService] = {}
    fixture_payloads: dict[str, dict[str, Any]] = {}

    recorder.field("topology", scenario.topology)
    recorder.field("scenario_file", str(scenario.path.relative_to(ROOT)))
    recorder.field("topology_file", str(topology.path.relative_to(ROOT)))
    for note in scenario.notes:
        recorder.note(note)

    recorder.event("run_started", "info", f"Scenario {scenario.name!r} started")
    print_progress(f"Scenario {scenario.name} (run-id: {run_id})")

    try:
        print_progress("Pre-cleaning topology")
        preclean_topology(recorder, topology, context)
        print_progress("Setting up topology")
        setup_attempted = True
        setup_ok = setup_topology(recorder, topology, context)
        if not setup_ok:
            status = "failed"
            should_exit = True
            skip_reason = "Skipped because topology setup failed."

        if not should_exit:
            recorder.assertion(
                "topology_context_ready",
                "passed",
                0,
                f"Resolved namespaces: {', '.join(resolved_topology_namespaces(topology, context, scenario_name=scenario.name))}.",
            )
            collect_namespace_snapshots(recorder, context, "setup")

        if not should_exit:
            for fixture_name in scenario.fixtures:
                print_progress(f"Setting up fixture {fixture_name}")
                started_ms = now_ms()
                try:
                    fixture_payload = setup_fixture(
                        recorder,
                        fixtures_registry[fixture_name],
                        scenario=scenario,
                        topology=topology,
                        context=context,
                        run_state=run_state,
                    )
                except ScenarioError as exc:
                    recorder.assertion(
                        f"fixture_{slugify(fixture_name)}_ready",
                        "failed",
                        now_ms() - started_ms,
                        str(exc),
                    )
                    status = "failed"
                    should_exit = True
                    skip_reason = f"Skipped because fixture {fixture_name} failed to start."
                    break
                fixture_payloads[fixture_name] = fixture_payload
                run_state.set_context(context)
                recorder.assertion(
                    f"fixture_{slugify(fixture_name)}_ready",
                    "passed",
                    now_ms() - started_ms,
                    f"Fixture {fixture_name} started.",
                )

        if not should_exit:
            for service_spec in scenario.services:
                started_ms = now_ms()
                print_progress(f"Launching service {service_spec.name} in role {service_spec.role}")
                try:
                    service = launch_composition_service(
                        recorder,
                        service_spec,
                        scenario=scenario,
                        topology=topology,
                        context=context,
                        fixture_payloads=fixture_payloads,
                        run_state=run_state,
                    )
                except ScenarioError as exc:
                    recorder.assertion(
                        f"launch_service_{slugify(service_spec.name)}",
                        "failed",
                        now_ms() - started_ms,
                        str(exc),
                    )
                    status = "failed"
                    should_exit = True
                    skip_reason = f"Skipped because service {service_spec.name} failed to launch."
                    break
                services[service_spec.name] = service
                run_state.set_context(context)
                recorder.field(service_context_key(service_spec.name, "namespace"), service.namespace)
                alive, details = service_launch_status(service)
                recorder.assertion(
                    f"launch_service_{slugify(service_spec.name)}",
                    "passed" if alive else "failed",
                    now_ms() - started_ms,
                    details,
                )
                if not alive:
                    status = "failed"
                    should_exit = True
                    skip_reason = f"Skipped because service {service_spec.name} did not become ready."
                    break

        if not should_exit:
            for index, step in enumerate(scenario.steps, start=1):
                next_step_index = index
                print_progress(f"Step {index}/{len(scenario.steps)}: {step.name}")
                started_ms = now_ms()
                try:
                    success = execute_probe_step(
                        recorder,
                        step,
                        context,
                        scenario=scenario,
                        probes=probe_registry,
                        run_state=run_state,
                    )
                except ScenarioError as exc:
                    recorder.assertion(step.name, "failed", now_ms() - started_ms, str(exc))
                    status = "failed"
                    skip_reason = f"Skipped because step {step.name} could not start."
                    break
                if not success:
                    status = "failed"
                    skip_reason = f"Skipped because step {step.name} failed."
                    break
                for service_name, service in services.items():
                    alive, details = service_status(service)
                    if not alive:
                        recorder.assertion(
                            f"service_alive_after_{slugify(service_name)}_{slugify(step.name)}",
                            "failed",
                            0,
                            details,
                        )
                        status = "failed"
                        skip_reason = f"Skipped because service {service_name} stopped after step {step.name}."
                        break
                if status != "passed":
                    break

            if skip_reason is not None and next_step_index < len(scenario.steps):
                record_skipped_steps(recorder, scenario.steps[next_step_index:], reason=skip_reason)

            print_progress("Collecting final snapshots")
            collect_namespace_snapshots(recorder, context, "final")
            for service_name, service in services.items():
                alive, details = service_status(service)
                if not alive:
                    recorder.assertion(
                        f"service_alive_before_cleanup_{slugify(service_name)}",
                        "failed",
                        0,
                        details,
                    )
                    status = "failed"
        elif skip_reason is not None and next_step_index < len(scenario.steps):
            record_skipped_steps(recorder, scenario.steps[next_step_index:], reason=skip_reason)
    except ScenarioError as exc:
        recorder.event("orchestrator_error", "error", str(exc))
        recorder.note(f"orchestrator_error={exc}")
        if status == "passed":
            status = "error"
    finally:
        try:
            copy_fixture_artifacts(recorder, fixture_payloads)

            for service_name, service in reversed(list(services.items())):
                print_progress(f"Stopping service {service_name}")
                started_ms = now_ms()
                service_stop_status, service_stop_details = stop_service(
                    service,
                    timeout_s=service_stop_timeout_s,
                )
                recorder.assertion(
                    f"stop_service_{slugify(service_name)}",
                    service_stop_status,
                    now_ms() - started_ms,
                    service_stop_details,
                )
                if service_stop_status != "passed" and status == "passed":
                    status = "error"

            for fixture_name, payload in reversed(list(fixture_payloads.items())):
                started_ms = now_ms()
                stop_status, stop_details = stop_fixture(recorder, payload)
                recorder.assertion(
                    f"stop_fixture_{slugify(fixture_name)}",
                    stop_status,
                    now_ms() - started_ms,
                    stop_details,
                )
                if stop_status != "passed" and status == "passed":
                    status = "error"

            if setup_attempted:
                if keep_topology:
                    print_progress("Leaving topology running")
                    recorder.note("topology_left_running=1")
                    recorder.event("teardown_skipped", "info", "Topology left running by request")
                else:
                    print_progress("Tearing down topology")
                    teardown_ok = teardown_topology(recorder, topology, context)
                    if not teardown_ok and status == "passed":
                        status = "error"
        except ScenarioError as exc:
            recorder.event("teardown_error", "error", str(exc))
            recorder.note(f"teardown_error={exc}")
            if status == "passed":
                status = "error"
        finally:
            if not keep_topology:
                shutil.rmtree(lab_root, ignore_errors=True)

        recorder.metric("step_count", len(scenario.steps))
        recorder.event("run_finished", status, f"Scenario finished with status {status}")
        run_state.set_context(context)
        recorder.finalize(status)
        try:
            apply_tree_ownership(recorder.run_dir, artifact_owner)
        except OSError as exc:
            recorder.note(f"artifact_ownership_error={exc}")
            if status == "passed":
                status = "error"
                recorder.finalize(status)

    print_progress("Run complete")
    print(f"[SUMMARY] {recorder.run_dir / 'summary.txt'}")
    print((recorder.run_dir / "summary.txt").read_text(encoding="utf-8"), end="")
    return 0 if status == "passed" else 1
