from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lib.core.models import ScenarioError
from lib.core.paths import ROOT
from lib.core.util import now_ms, slugify
from lib.tools.probe_runner import (
    ActionOutcome,
    ActionSchema,
    ManagedProcess,
    ProbeSequenceState,
    action_id,
    action_number,
    action_timeout_s,
    capture_path,
    materialize_argv,
    optional_string,
    record_assertion,
    register_probe_action,
    require_string,
    require_string_list,
    resolve_action_value,
)

MAPPING_DPORT_RE = re.compile(r"\b(tcp|udp)\s+dport\s+(\d+)\b")
DNAT_TARGET_RE = re.compile(r"\bdnat to (?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d+)\b")
UPNPC_EXTERNAL_IP_RE = re.compile(r"\bExternalIPAddress\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\b")
UPNPC_LOCAL_IP_RE = re.compile(r"\bLocal LAN ip address\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\b")

_REGISTERED = False


@dataclass(frozen=True)
class PortMapping:
    protocol: str
    external_port: str
    target_ip: str
    target_port: str
    line: str


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


def run_capture_command(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    command = materialize_argv(action.get("argv"), state, field_name="argv")
    destination = optional_string(action, "destination", state, default=f"{slugify(name)}.txt")
    label = optional_string(action, "label", state, default=name.replace("_", " "))
    kind = optional_string(action, "kind", state, default="command-output")
    path = capture_path(state.recorder, destination)

    with path.open("w", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(command)}\n\n")
        try:
            completed = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, text=True, check=False)
            rc = completed.returncode
        except OSError as exc:
            handle.write(f"ERROR: {exc}\n")
            rc = 127
    capture = state.recorder.record_command_capture(label, kind, path)
    details = f"Command exited {rc}."
    if capture:
        details += f" Capture: {capture}"
    if rc == 0:
        record_assertion(state.recorder, name, "passed", started_ms, details)
    else:
        record_assertion(state.recorder, name, "failed", started_ms, details)
    if rc != 0:
        return ActionOutcome(success=False, details=details)
    return ActionOutcome(success=True, details=details)


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


def timeout_output(exc: subprocess.TimeoutExpired) -> str:
    output = ""
    for chunk in (exc.stdout, exc.stderr):
        if isinstance(chunk, bytes):
            output += chunk.decode("utf-8", errors="replace")
        elif isinstance(chunk, str):
            output += chunk
    return output


def upnpc_discovery_fields(output: str) -> tuple[bool, str, str]:
    valid_igd = "Found valid IGD" in output
    external_ip_match = UPNPC_EXTERNAL_IP_RE.search(output)
    local_ip_match = UPNPC_LOCAL_IP_RE.search(output)
    return (
        valid_igd,
        external_ip_match.group(1) if external_ip_match else "",
        local_ip_match.group(1) if local_ip_match else "",
    )


def run_assert_igd_discovery(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    namespace = require_string(action.get("namespace"), field_name="namespace", state=state)
    timeout_s = action_timeout_s(action, 10)
    destination = optional_string(action, "capture", state, default="upnpc.txt")
    label = optional_string(action, "label", state, default="IGD discovery")
    output_name = optional_string(action, "output", state, default="igd_external_ip")
    command = ["ip", "netns", "exec", namespace, "upnpc", "-s"]
    output_path = capture_path(state.recorder, destination)
    deadline = time.monotonic() + timeout_s
    attempts = 0
    last_rc = 127
    last_output = ""
    external_ip = ""
    local_ip = ""
    valid_igd = False

    while True:
        attempts += 1
        remaining_s = max(1.0, deadline - time.monotonic()) if timeout_s > 0 else 1.0
        try:
            completed = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=remaining_s,
            )
            last_rc = completed.returncode
            last_output = completed.stdout or ""
        except subprocess.TimeoutExpired as exc:
            last_rc = 124
            last_output = timeout_output(exc)
            last_output += f"\nERROR: command timed out after {remaining_s:.1f}s\n"
        except OSError as exc:
            last_rc = 127
            last_output = f"ERROR: {exc}\n"

        valid_igd, external_ip, local_ip = upnpc_discovery_fields(last_output)
        with output_path.open("w", encoding="utf-8") as handle:
            handle.write(f"$ {shlex.join(command)}\n\n")
            handle.write(last_output)

        if last_rc == 0 and valid_igd and external_ip:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(1)

    capture = state.recorder.record_command_capture(label, "command-output", output_path)
    details = f"Capture: {capture}" if capture else "No command output was captured."
    if last_rc == 0 and valid_igd and external_ip:
        state.outputs[output_name] = external_ip
        if local_ip:
            state.outputs[f"{output_name}_local_ip"] = local_ip
        state.recorder.metric("igd_discovery_attempts", attempts)
        record_assertion(
            state.recorder,
            name,
            "passed",
            started_ms,
            f"Discovered IGD from namespace {namespace} with external IP {external_ip}. {details}",
        )
        return ActionOutcome(True, details)

    if last_rc != 0:
        failure = f"upnpc -s exited {last_rc}"
    elif not valid_igd:
        failure = "upnpc output did not report a valid IGD"
    elif not external_ip:
        failure = "upnpc output did not report ExternalIPAddress"
    else:
        failure = "upnpc discovery failed"
    details = f"{failure} after {attempts} attempt(s) in namespace {namespace}. {details}"
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def register_default_probe_actions() -> None:
    global _REGISTERED
    if _REGISTERED:
        return

    register_probe_action(
        "assert_igd_discovery",
        ActionSchema(
            required=frozenset({"namespace"}),
            optional=frozenset({"capture", "label", "output", "timeout_s"}),
        ),
        run_assert_igd_discovery,
    )
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
    register_probe_action(
        "capture_command",
        ActionSchema(
            required=frozenset({"argv"}),
            optional=frozenset({"destination", "kind", "label"}),
        ),
        run_capture_command,
    )
    _REGISTERED = True
