from __future__ import annotations

from typing import Any

from lib.loaders.context_loader import (
    ensure_role_exists,
    fixture_context_key,
    fixture_record_payload,
    require_string,
    resolve_value,
    role_context_key,
    update_context_from_outputs,
)
from .lifecycle import copy_named_artifacts, run_command, shell_function_command
from lib.core.models import FixtureSpec, ScenarioError, ScenarioSpec, TopologySpec
from lib.reporting.result_recorder import ResultRecorder, RunState
from lib.core.util import ensure_int, slugify, strip_cidr


def setup_fixture(
    recorder: ResultRecorder,
    fixture: FixtureSpec,
    *,
    scenario: ScenarioSpec,
    topology: TopologySpec,
    context: dict[str, str],
    run_state: RunState,
) -> dict[str, Any]:
    options = resolve_value(fixture.options, context, scenario_name=scenario.name)
    outputs: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    capture_name = f"fixtures/{slugify(fixture.name)}-up.txt"
    capture_path = recorder.command_capture_path(capture_name)

    if fixture.kind == "local-bootstrap":
        role_name = ensure_role_exists(
            require_string(options.get("role"), field_name="fixture.options.role", scenario_path=fixture.path or scenario.path),
            topology=topology,
            object_path=fixture.path or scenario.path,
            field_name=f"fixture {fixture.name!r}.options.role",
        )
        namespace = context[role_context_key(role_name, "namespace")]
        bind_ip = strip_cidr(require_string(options.get("bind_ip"), field_name="fixture.options.bind_ip", scenario_path=fixture.path or scenario.path))
        port = ensure_int(options.get("port", 4222), field_name=f"fixture {fixture.name!r}.options.port")
        timeout_s = ensure_int(options.get("timeout_s", 10), field_name=f"fixture {fixture.name!r}.options.timeout_s")
        bootstrap_script = require_string(
            options.get("bootstrap_script"),
            field_name="fixture.options.bootstrap_script",
            scenario_path=fixture.path or scenario.path,
        )
        pidfile = require_string(options.get("pidfile"), field_name="fixture.options.pidfile", scenario_path=fixture.path or scenario.path)
        logfile = require_string(options.get("logfile"), field_name="fixture.options.logfile", scenario_path=fixture.path or scenario.path)
        rc = run_command(
            shell_function_command(
                "vnet_fixture_start_local_bootstrap",
                namespace,
                bind_ip,
                str(port),
                pidfile,
                logfile,
                str(timeout_s),
                bootstrap_script,
            ),
            capture_path,
        )
        capture = recorder.record_command_capture(f"Fixture setup ({fixture.name})", "command-output", capture_path)
        if rc != 0:
            details = f"Fixture {fixture.name!r} failed to start local bootstrap."
            if capture:
                details += f" Capture: {capture}"
            raise ScenarioError(details)
        outputs = {
            "role": role_name,
            "namespace": namespace,
            "bootstrap_host": bind_ip,
            "bootstrap_port": port,
            "bootstrap_endpoint": f"{bind_ip}:{port}",
        }
        artifacts = {"pidfile": pidfile, "logfile": logfile}
    elif fixture.kind == "miniupnpd":
        role_name = ensure_role_exists(
            require_string(options.get("role"), field_name="fixture.options.role", scenario_path=fixture.path or scenario.path),
            topology=topology,
            object_path=fixture.path or scenario.path,
            field_name=f"fixture {fixture.name!r}.options.role",
        )
        namespace = context[role_context_key(role_name, "namespace")]
        pidfile = require_string(options.get("pidfile"), field_name="fixture.options.pidfile", scenario_path=fixture.path or scenario.path)
        logfile = require_string(options.get("logfile"), field_name="fixture.options.logfile", scenario_path=fixture.path or scenario.path)
        configfile = require_string(options.get("configfile"), field_name="fixture.options.configfile", scenario_path=fixture.path or scenario.path)
        ext_iface = require_string(options.get("ext_iface"), field_name="fixture.options.ext_iface", scenario_path=fixture.path or scenario.path)
        listen_iface = require_string(options.get("listen_iface"), field_name="fixture.options.listen_iface", scenario_path=fixture.path or scenario.path)
        uuid = require_string(options.get("uuid"), field_name="fixture.options.uuid", scenario_path=fixture.path or scenario.path)
        friendly_name = require_string(
            options.get("friendly_name"),
            field_name="fixture.options.friendly_name",
            scenario_path=fixture.path or scenario.path,
        )
        ext_ip = require_string(options.get("ext_ip"), field_name="fixture.options.ext_ip", scenario_path=fixture.path or scenario.path)
        rc = run_command(
            shell_function_command(
                "vnet_fixture_start_miniupnpd_instance",
                namespace,
                configfile,
                pidfile,
                logfile,
                ext_iface,
                listen_iface,
                uuid,
                friendly_name,
                ext_ip,
            ),
            capture_path,
        )
        capture = recorder.record_command_capture(f"Fixture setup ({fixture.name})", "command-output", capture_path)
        if rc != 0:
            details = f"Fixture {fixture.name!r} failed to start miniupnpd."
            if capture:
                details += f" Capture: {capture}"
            raise ScenarioError(details)

        discovery_role = options.get("discovery_role")
        discovery_log = options.get("discovery_log")
        if isinstance(discovery_role, str) and discovery_role and isinstance(discovery_log, str) and discovery_log:
            discovery_role = ensure_role_exists(
                discovery_role,
                topology=topology,
                object_path=fixture.path or scenario.path,
                field_name=f"fixture {fixture.name!r}.options.discovery_role",
            )
            discovery_namespace = context[role_context_key(discovery_role, "namespace")]
            discovery_expected_external_ip = require_string(
                options.get("discovery_expected_external_ip", ext_ip),
                field_name="fixture.options.discovery_expected_external_ip",
                scenario_path=fixture.path or scenario.path,
            )
            discovery_bind_ip = ""
            if options.get("discovery_bind_ip") is not None:
                discovery_bind_ip = strip_cidr(
                    require_string(
                        options.get("discovery_bind_ip"),
                        field_name="fixture.options.discovery_bind_ip",
                        scenario_path=fixture.path or scenario.path,
                    )
                )
            discovery_timeout_s = ensure_int(
                options.get("discovery_timeout_s", 10),
                field_name=f"fixture {fixture.name!r}.options.discovery_timeout_s",
            )
            discovery_capture_name = f"fixtures/{slugify(fixture.name)}-discovery.txt"
            discovery_capture_path = recorder.command_capture_path(discovery_capture_name)
            discovery_rc = run_command(
                shell_function_command(
                    "vnet_fixture_wait_for_discovery",
                    discovery_namespace,
                    discovery_log,
                    str(discovery_timeout_s),
                    discovery_expected_external_ip,
                    discovery_bind_ip,
                ),
                discovery_capture_path,
            )
            discovery_capture = recorder.record_command_capture(
                f"Fixture discovery wait ({fixture.name})",
                "command-output",
                discovery_capture_path,
            )
            if discovery_rc != 0:
                stop_capture_name = f"fixtures/{slugify(fixture.name)}-down-after-discovery-failure.txt"
                stop_capture_path = recorder.command_capture_path(stop_capture_name)
                stop_rc = run_command(shell_function_command("vnet_fixture_stop_pidfile", pidfile), stop_capture_path)
                recorder.record_command_capture(
                    f"Fixture teardown after failed discovery ({fixture.name})",
                    "command-output",
                    stop_capture_path,
                )
                recorder.note(f"fixture_discovery_timeout:{fixture.name}:stop_exit_code={stop_rc}")
                details = (
                    f"Fixture {fixture.name!r} did not become discoverable from role {discovery_role!r} "
                    f"with external IP {discovery_expected_external_ip!r}."
                )
                if discovery_capture:
                    details += f" Capture: {discovery_capture}"
                raise ScenarioError(details)
            outputs["discovery_role"] = discovery_role
            outputs["discovery_namespace"] = discovery_namespace
            outputs["discovery_expected_external_ip"] = discovery_expected_external_ip
            if discovery_bind_ip:
                outputs["discovery_bind_ip"] = discovery_bind_ip
            artifacts["discovery_log"] = discovery_log

        outputs.update({"role": role_name, "namespace": namespace, "external_ip": ext_ip})
        artifacts.update({"pidfile": pidfile, "logfile": logfile, "configfile": configfile})
    else:
        raise ScenarioError(f"Unsupported fixture kind {fixture.kind!r}")

    payload = fixture_record_payload(fixture, outputs, artifacts, options)
    run_state.set_fixture(fixture.name, payload)
    update_context_from_outputs(context, fixture_context_key(fixture.name, ""), outputs)
    return payload


def stop_fixture(
    recorder: ResultRecorder,
    fixture_payload: dict[str, Any],
) -> tuple[str, str]:
    fixture_name = str(fixture_payload["name"])
    artifacts = fixture_payload.get("artifacts", {})
    pidfile = artifacts.get("pidfile")
    if not isinstance(pidfile, str) or not pidfile:
        return "passed", f"Fixture {fixture_name} has no pidfile to stop."
    capture_name = f"fixtures/{slugify(fixture_name)}-down.txt"
    capture_path = recorder.command_capture_path(capture_name)
    rc = run_command(shell_function_command("vnet_fixture_stop_pidfile", pidfile), capture_path)
    capture = recorder.record_command_capture(f"Fixture teardown ({fixture_name})", "command-output", capture_path)
    status = "passed" if rc == 0 else "failed"
    details = f"Fixture {fixture_name} stop command exited {rc}."
    if capture:
        details += f" Capture: {capture}"
    return status, details


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
