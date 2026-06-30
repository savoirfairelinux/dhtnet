from __future__ import annotations

import subprocess
from typing import Any

from lib.core.models import ScenarioError
from lib.core.util import now_ms
from lib.tools.probe_runner import (
    ActionOutcome,
    ActionSchema,
    ProbeSequenceState,
    action_id,
    record_assertion,
    register_probe_action,
    require_string,
    require_string_list,
    resolve_action_value,
)


def require_route_expectations(value: Any, *, field_name: str, state: ProbeSequenceState) -> list[dict[str, str]]:
    resolved = resolve_action_value(value, state)
    if not isinstance(resolved, list) or not resolved:
        raise ScenarioError(f"Probe {state.probe.name!r} requires a non-empty list field {field_name}")
    expectations: list[dict[str, str]] = []
    for index, item in enumerate(resolved):
        if not isinstance(item, dict):
            raise ScenarioError(f"Probe {state.probe.name!r} requires object entries for {field_name}[{index}]")
        destination = item.get("destination")
        if not isinstance(destination, str) or not destination:
            raise ScenarioError(f"Probe {state.probe.name!r} requires {field_name}[{index}].destination")
        expectation = {"destination": destination}
        for key in ("via", "dev", "metric"):
            raw = item.get(key)
            if raw is not None:
                if not isinstance(raw, str) or not raw:
                    raise ScenarioError(f"Probe {state.probe.name!r} requires string {field_name}[{index}].{key}")
                expectation[key] = raw
        expectations.append(expectation)
    return expectations


def list_namespaces() -> tuple[int, set[str], str]:
    try:
        completed = subprocess.run(["ip", "netns", "list"], text=True, capture_output=True, check=False)
    except OSError as exc:
        return 127, set(), str(exc)
    namespaces = {
        line.split()[0]
        for line in completed.stdout.splitlines()
        if line.split()
    }
    return completed.returncode, namespaces, completed.stderr.strip()


def run_assert_namespaces_exist(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    names = require_string_list(action.get("namespaces"), field_name="namespaces", state=state)
    rc, existing, error = list_namespaces()
    missing = [namespace for namespace in names if namespace not in existing]
    name = action_id(action)

    if rc == 0 and not missing:
        details = f"Namespaces {', '.join(names)} are present."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    if rc != 0:
        details = f"Could not list namespaces: ip netns list exited {rc}. {error}".strip()
    else:
        details = f"Required namespace(s) missing: {', '.join(missing)}."
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def route_lines(namespace: str, ip_flag: str) -> tuple[int, list[str], str]:
    command = ["ip", "-n", namespace]
    if ip_flag:
        command.append(ip_flag)
    command.extend(["route", "show"])
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError as exc:
        return 127, [], str(exc)
    return completed.returncode, [line.strip() for line in completed.stdout.splitlines() if line.strip()], completed.stderr.strip()


def route_line_matches(line: str, expectation: dict[str, str]) -> bool:
    destination = expectation["destination"]
    if destination == "default":
        if not line.startswith("default "):
            return False
    elif not line.startswith(f"{destination} "):
        return False
    tokens = line.split()
    for key in ("via", "dev", "metric"):
        value = expectation.get(key)
        if value is None:
            continue
        if key not in tokens:
            return False
        if tokens[tokens.index(key) + 1:tokens.index(key) + 2] != [value]:
            return False
    return True


def run_assert_routes(action: dict[str, Any], state: ProbeSequenceState, *, ip_version: str, ip_flag: str) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    namespace = require_string(action.get("namespace"), field_name="namespace", state=state)
    expected_routes = require_route_expectations(action.get("expected_routes"), field_name="expected_routes", state=state)
    rc, lines, error = route_lines(namespace, ip_flag)
    if rc != 0:
        details = f"Could not inspect IPv{ip_version} routes in namespace {namespace}: ip route exited {rc}. {error}".strip()
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    missing = [
        expectation
        for expectation in expected_routes
        if not any(route_line_matches(line, expectation) for line in lines)
    ]
    if not missing:
        details = f"All expected IPv{ip_version} routes are present in namespace {namespace}."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    details = f"Missing route expectation(s): {missing}. Observed routes: {lines}"
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def run_assert_ipv4_routes(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    return run_assert_routes(action, state, ip_version="4", ip_flag="-4")


def run_assert_ipv6_routes(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    return run_assert_routes(action, state, ip_version="6", ip_flag="-6")


def register_actions() -> None:
    register_probe_action(
        "assert_ipv4_routes",
        ActionSchema(
            required=frozenset({"expected_routes", "namespace"}),
        ),
        run_assert_ipv4_routes,
    )
    register_probe_action(
        "assert_ipv6_routes",
        ActionSchema(
            required=frozenset({"expected_routes", "namespace"}),
        ),
        run_assert_ipv6_routes,
    )
    register_probe_action(
        "assert_namespaces_exist",
        ActionSchema(
            required=frozenset({"namespaces"}),
        ),
        run_assert_namespaces_exist,
    )
