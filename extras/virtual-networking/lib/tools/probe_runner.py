from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from lib.core.models import ProbeSpec, ScenarioError
from lib.core.paths import ROOT
from lib.reporting.result_recorder import ResultRecorder, initialize_result_layout
from lib.core.util import now_ms, slugify

EXACT_PLACEHOLDER_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")
MAPPING_DPORT_RE = re.compile(r"\b(tcp|udp)\s+dport\s+(\d+)\b")
DNAT_TARGET_RE = re.compile(r"\bdnat to (?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d+)\b")
UPNPC_EXTERNAL_IP_RE = re.compile(r"\bExternalIPAddress\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\b")
UPNPC_LOCAL_IP_RE = re.compile(r"\bLocal LAN ip address\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\b")


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
class PortMapping:
    protocol: str
    external_port: str
    target_ip: str
    target_port: str
    line: str


@dataclass(frozen=True)
class ActionSchema:
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


COMMON_ACTION_FIELDS = frozenset({"id", "type"})
ACTION_SCHEMAS = {
    "assert_igd_discovery": ActionSchema(
        required=frozenset({"namespace"}),
        optional=frozenset({"capture", "label", "output", "timeout_s"}),
    ),
    "assert_ipv4_routes": ActionSchema(
        required=frozenset({"expected_routes", "namespace"}),
    ),
    "assert_namespaces_exist": ActionSchema(
        required=frozenset({"namespaces"}),
    ),
    "assert_upnp_mappings": ActionSchema(
        required=frozenset({"router_namespace"}),
        optional=frozenset({"actor_namespace", "capture", "output", "router_external_ip", "session_capture", "timeout_s"}),
    ),
    "capture_command": ActionSchema(
        required=frozenset({"argv"}),
        optional=frozenset({"destination", "kind", "label"}),
    ),
    "dhtnet_dsh_roundtrip": ActionSchema(
        required=frozenset({"bootstrap_host", "bootstrap_port", "client_namespace", "peer_id"}),
        optional=frozenset({"capture", "label", "output", "startup_delay_s", "timeout_s", "token"}),
    ),
}


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


def route_lines(namespace: str) -> tuple[int, list[str], str]:
    try:
        completed = subprocess.run(
            ["ip", "-n", namespace, "route", "show"],
            text=True,
            capture_output=True,
            check=False,
        )
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


def run_assert_ipv4_routes(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    namespace = require_string(action.get("namespace"), field_name="namespace", state=state)
    expected_routes = require_route_expectations(action.get("expected_routes"), field_name="expected_routes", state=state)
    rc, lines, error = route_lines(namespace)
    if rc != 0:
        details = f"Could not inspect routes in namespace {namespace}: ip route exited {rc}. {error}".strip()
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    missing = [
        expectation
        for expectation in expected_routes
        if not any(route_line_matches(line, expectation) for line in lines)
    ]
    if not missing:
        details = f"All expected IPv4 routes are present in namespace {namespace}."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    details = f"Missing route expectation(s): {missing}. Observed routes: {lines}"
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


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


def append_build_dir_candidate(candidates: list[Path], candidate: Path) -> None:
    if not candidate.is_dir():
        return
    normalized = candidate.resolve()
    if normalized not in candidates:
        candidates.append(normalized)


def find_tool_in_build_dir(build_dir: Path, binary_name: str) -> Path | None:
    for candidate in (
        build_dir / binary_name,
        build_dir / "bin" / binary_name,
        build_dir / "Debug" / binary_name,
        build_dir / "Release" / binary_name,
        build_dir / "RelWithDebInfo" / binary_name,
        build_dir / "MinSizeRel" / binary_name,
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    for candidate in build_dir.rglob(binary_name):
        try:
            relative_depth = len(candidate.relative_to(build_dir).parts)
        except ValueError:
            continue
        if relative_depth <= 5 and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def resolve_dhtnet_tool(binary_name: str, env_var_name: str) -> Path:
    env_value = os.environ.get(env_var_name)
    if env_value:
        path = Path(env_value)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ScenarioError(f"{env_var_name} points to a non-executable path: {env_value}")
        return path

    repo_root = Path(os.environ.get("VNET_REPO_ROOT", str(ROOT.parent.parent)))
    candidates: list[Path] = []
    build_dir = os.environ.get("BUILD_DIR") or os.environ.get("DHTNET_BUILD_DIR")
    if build_dir:
        append_build_dir_candidate(candidates, Path(build_dir))
    append_build_dir_candidate(candidates, repo_root / "build")
    for pattern in ("build-*", "cmake-build*"):
        for candidate in repo_root.glob(pattern):
            append_build_dir_candidate(candidates, candidate)

    for candidate in candidates:
        found = find_tool_in_build_dir(candidate, binary_name)
        if found is not None:
            return found

    found_path = shutil.which(binary_name)
    if found_path:
        return Path(found_path)

    raise ScenarioError(
        f"Could not find {binary_name}. Build dhtnet first or set {env_var_name}, DHTNET_BUILD_DIR, or PATH."
    )


def bootstrap_target(host: str, port: str) -> str:
    return host if port == "4222" else f"{host}:{port}"


def wait_for_file_pattern(path: Path, pattern: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() <= deadline:
        if path.is_file() and pattern in path.read_text(encoding="utf-8", errors="replace"):
            return True
        time.sleep(1)
    return False


def run_dhtnet_dsh_roundtrip(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    timeout_s = action_timeout_s(action, 20)
    startup_delay_s = action_number(action, "startup_delay_s", 2)
    output_name = optional_string(action, "output", state, default="roundtrip_token")
    client_namespace = require_string(action.get("client_namespace"), field_name="client_namespace", state=state)
    peer_id = require_string(action.get("peer_id"), field_name="peer_id", state=state)
    bootstrap_host = require_string(action.get("bootstrap_host"), field_name="bootstrap_host", state=state)
    bootstrap_port = require_string(action.get("bootstrap_port"), field_name="bootstrap_port", state=state)
    target = bootstrap_target(bootstrap_host, bootstrap_port)
    destination = optional_string(action, "capture", state, default="wan-dsh-client.txt")
    label = optional_string(action, "label", state, default="WAN dsh client output")
    token = optional_string(action, "token", state, default=f"dhtnet-vnet-{time.time_ns()}")

    try:
        dsh_bin = resolve_dhtnet_tool("dsh", "DHTNET_DSH_BIN")
        crtmgr_bin = resolve_dhtnet_tool("dhtnet-crtmgr", "DHTNET_CRTMGR_BIN")
        client_dir = Path(tempfile.mkdtemp(prefix="dhtnet-probe-client."))
        state.temp_dirs.append(client_dir)
        client_cache_dir = client_dir / "cache"
        client_home_dir = client_dir / "home"
        client_cache_dir.mkdir(parents=True, exist_ok=True)
        client_home_dir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [str(crtmgr_bin), "--setup", "-o", str(client_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ScenarioError(
                f"{crtmgr_bin} --setup exited {completed.returncode}: {completed.stderr.strip()}"
            )

        client_cert = client_dir / "id" / "id-server.crt"
        client_key = client_dir / "id" / "id-server.pem"
        command = [
            "ip",
            "netns",
            "exec",
            client_namespace,
            str(dsh_bin),
            "-b",
            target,
            "-c",
            str(client_cert),
            "-p",
            str(client_key),
            "-s",
            "/bin/cat",
            peer_id,
        ]
        output_path = capture_path(state.recorder, destination)
        output_handle = output_path.open("w", encoding="utf-8")
        output_handle.write(f"$ {shlex.join(command)}\n\n")
        output_handle.flush()
        client_env = {
            **os.environ,
            "DHTNET_CACHE_DIR": str(client_cache_dir),
            "HOME": str(client_home_dir),
        }
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=output_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env=client_env,
        )
        state.processes.append(ManagedProcess(process=process, log_handle=output_handle))

        time.sleep(startup_delay_s)
        if process.stdin is None:
            raise ScenarioError("dsh client stdin was not opened")
        process.stdin.write(f"{token}\n")
        process.stdin.flush()
    except (OSError, BrokenPipeError, ScenarioError) as exc:
        details = f"Could not start WAN dsh roundtrip: {exc}"
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    if wait_for_file_pattern(output_path, token, timeout_s):
        state.recorder.record_command_capture(label, "command-output", output_path)
        state.outputs[output_name] = token
        state.recorder.note(f"bootstrap_target={target}")
        details = f"Client namespace dsh session connected to the actor and echoed token {token}."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    capture = state.recorder.record_command_capture(label, "command-output", output_path)
    details = f"Client namespace dsh session did not echo token {token}."
    if capture:
        details += f" Capture: {capture}"
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def namespace_ipv4_addresses(namespace: str) -> set[str]:
    completed = subprocess.run(
        ["ip", "-n", namespace, "-o", "-4", "addr", "show"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return set()
    addresses: set[str] = set()
    for token in completed.stdout.split():
        if "/" in token and token.count(".") == 3:
            addresses.add(token.split("/", 1)[0])
    return addresses


def mapped_ports(router_namespace: str) -> tuple[list[PortMapping], str]:
    completed = subprocess.run(
        ["ip", "netns", "exec", router_namespace, "nft", "list", "chain", "ip", "miniupnpd", "prerouting"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return [], completed.stderr
    mappings: dict[tuple[str, str], PortMapping] = {}
    for line in completed.stdout.splitlines():
        dport_match = MAPPING_DPORT_RE.search(line)
        if not dport_match:
            continue
        dnat_match = DNAT_TARGET_RE.search(line)
        mapping = PortMapping(
            protocol=dport_match.group(1).lower(),
            external_port=dport_match.group(2),
            target_ip=dnat_match.group(1) if dnat_match and dnat_match.group(1) else "",
            target_port=dnat_match.group(2) if dnat_match else "",
            line=line.strip(),
        )
        mappings[(mapping.protocol, mapping.external_port)] = mapping
    return sorted(mappings.values(), key=lambda item: int(item.external_port)), completed.stdout


def session_srflx_ports(capture_path: Path, router_external_ip: str) -> set[tuple[str, str]]:
    if not capture_path.is_file():
        return set()
    ports: set[tuple[str, str]] = set()
    for line in capture_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if " typ srflx" not in line or router_external_ip not in line:
            continue
        parts = line.split()
        for index, token in enumerate(parts):
            if token.upper() in {"TCP", "UDP"} and index + 3 < len(parts) and parts[index + 2] == router_external_ip:
                ports.add((token.lower(), parts[index + 3]))
    return ports


def run_assert_upnp_mappings(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    router_namespace = require_string(action.get("router_namespace"), field_name="router_namespace", state=state)
    actor_namespace = optional_string(action, "actor_namespace", state, default="")
    router_external_ip = optional_string(action, "router_external_ip", state, default="")
    session_capture = optional_string(action, "session_capture", state, default="")
    timeout_s = action_timeout_s(action, 20)
    destination = optional_string(action, "capture", state, default="mapped-ports.txt")
    output_name = optional_string(action, "output", state, default="mapped_ports")

    deadline = time.monotonic() + timeout_s
    mappings: list[PortMapping] = []
    actor_ips: set[str] = set()
    session_ports: set[tuple[str, str]] = set()
    session_capture_path = Path(session_capture) if session_capture else None
    requires_session_correlation = session_capture_path is not None and bool(router_external_ip)
    while time.monotonic() <= deadline:
        mappings, _raw = mapped_ports(router_namespace)
        if actor_namespace:
            actor_ips = namespace_ipv4_addresses(actor_namespace)
        if session_capture_path is not None and router_external_ip:
            session_ports = session_srflx_ports(session_capture_path, router_external_ip)
        actor_matches = (
            not actor_namespace
            or any(mapping.target_ip in actor_ips for mapping in mappings)
        )
        session_matches = (
            not requires_session_correlation
            or (
                bool(session_ports)
                and any((mapping.protocol, mapping.external_port) in session_ports for mapping in mappings)
            )
        )
        if mappings and actor_matches and session_matches:
            break
        time.sleep(1)

    output_path = capture_path(state.recorder, destination)
    output_lines = [
        json.dumps(
            {
                "protocol": mapping.protocol,
                "external_port": mapping.external_port,
                "target_ip": mapping.target_ip,
                "target_port": mapping.target_port,
                "line": mapping.line,
            },
            sort_keys=True,
        )
        for mapping in mappings
    ]
    output_path.write_text("\n".join(output_lines) + ("\n" if output_lines else ""), encoding="utf-8")
    state.recorder.record_command_capture("mapped UPnP ports", "command-output", output_path)
    state.outputs[output_name] = [mapping.external_port for mapping in mappings]

    router_ips = namespace_ipv4_addresses(router_namespace)
    if router_external_ip and router_external_ip not in router_ips:
        details = f"Router namespace {router_namespace} does not have expected external IP {router_external_ip}."
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    if requires_session_correlation and not session_ports:
        details = (
            "No server-reflexive ICE candidate ports for the router external IP were parsed from "
            f"{session_capture_path}. Mappings: {[mapping.line for mapping in mappings]}."
        )
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    if mappings and not actor_namespace:
        matching_mappings = [
            mapping
            for mapping in mappings
            if not requires_session_correlation or (mapping.protocol, mapping.external_port) in session_ports
        ]
        if matching_mappings:
            state.recorder.metric("mapped_port_count", len(mappings))
            details = f"At least one UPnP mapping exists on router external IP {router_external_ip or '<unspecified>'}."
            record_assertion(state.recorder, name, "passed", started_ms, details)
            return ActionOutcome(True, details)

    matching_mappings = [
        mapping
        for mapping in mappings
        if mapping.target_ip in actor_ips
        and (not requires_session_correlation or (mapping.protocol, mapping.external_port) in session_ports)
    ]
    if matching_mappings:
        state.recorder.metric("mapped_port_count", len(mappings))
        details = (
            "Observed UPnP mapping(s) whose DNAT target is the active actor namespace and whose "
            f"external port appears in the dhtnet session candidates: "
            f"{[f'{mapping.protocol}/{mapping.external_port}' for mapping in matching_mappings]}."
        )
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    details = (
        "No UPnP mapping for the active dhtnet session was observed. "
        f"Actor IPs: {sorted(actor_ips)}. Session srflx ports: {sorted(session_ports)}. "
        f"Mappings: {[mapping.line for mapping in mappings]}."
    )
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


ACTION_HANDLERS = {
    "assert_igd_discovery": run_assert_igd_discovery,
    "assert_ipv4_routes": run_assert_ipv4_routes,
    "assert_namespaces_exist": run_assert_namespaces_exist,
    "assert_upnp_mappings": run_assert_upnp_mappings,
    "capture_command": run_capture_command,
    "dhtnet_dsh_roundtrip": run_dhtnet_dsh_roundtrip,
}


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
