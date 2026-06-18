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

from .runner.models import ProbeSpec, ScenarioError
from .runner.paths import ROOT
from .runner.result_recorder import ResultRecorder, initialize_result_layout
from .runner.util import now_ms, slugify

EXACT_PLACEHOLDER_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")
UDP_DPORT_RE = re.compile(r"\budp\s+dport\s+(\d+)\b")


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
    outputs: dict[str, Any]
    outputs_file: Path | None
    summary_json: Path
    summary_txt: Path


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
    return f"captures/{path.relative_to(recorder.captures_dir).as_posix()}"


def record_assertion(
    recorder: ResultRecorder,
    name: str,
    status: str,
    started_ms: int,
    details: str,
) -> None:
    recorder.assertion(name, status, now_ms() - started_ms, details)


def run_capture_command(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    command = materialize_argv(action.get("argv"), state, field_name="argv")
    destination = optional_string(action, "destination", state, default=f"{slugify(action_id(action))}.txt")
    label = optional_string(action, "label", state, default=action_id(action).replace("_", " "))
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
    state.recorder.record_capture(label, kind, capture_reference(state.recorder, path))
    if rc != 0:
        state.recorder.note(f"capture_failed:{destination}:exit_code={rc}")
    allow_failure = bool(action.get("allow_failure", False))
    return ActionOutcome(success=rc == 0 or allow_failure, details=f"Command exited {rc}")


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


def run_capture_file(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    source: str | None
    if "source_input" in action:
        input_name = require_string(action["source_input"], field_name="source_input", state=state)
        value = state.optional_input(input_name)
        source = str(value) if value is not None else None
    else:
        source = optional_string(action, "source", state, default="")

    if not source and bool(action.get("skip_if_missing", False)):
        state.recorder.note(f"action_skipped:{action_id(action)}:source_missing")
        return ActionOutcome(True, "Skipped because source is missing.")

    started_ms = now_ms()
    name = action_id(action)
    if not source:
        details = "Capture source is missing."
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    source_path = Path(source)
    destination = optional_string(action, "destination", state, default=source_path.name)
    label = optional_string(action, "label", state, default=name.replace("_", " "))
    kind = optional_string(action, "kind", state, default="state-dump")

    if not source_path.is_file():
        details = f"Capture source is missing or unreadable: {source_path}"
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    destination_path = capture_path(state.recorder, destination)
    shutil.copy2(source_path, destination_path)
    state.recorder.record_capture(label, kind, capture_reference(state.recorder, destination_path))
    details = f"Captured {source_path}."
    record_assertion(state.recorder, name, "passed", started_ms, details)
    return ActionOutcome(True, details)


def read_actor_peer_id_from_file(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ScenarioError(f"{path}: actor output must be a JSON object")
    peer_id = payload.get("peer_id")
    if not isinstance(peer_id, str) or not peer_id:
        raise ScenarioError(f"{path}: actor output does not contain a non-empty peer_id")
    return peer_id


def run_read_actor_peer_id(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    output_name = optional_string(action, "output", state, default="actor_peer_id")
    peer_id_input = optional_string(action, "peer_id_input", state, default="actor_peer_id")
    actor_output_input = optional_string(action, "actor_output_input", state, default="actor_output")

    try:
        peer_id = state.optional_input(peer_id_input)
        if peer_id is None:
            actor_output = state.optional_input(actor_output_input)
            if actor_output is None:
                raise ScenarioError(
                    f"Probe requires either input {peer_id_input!r} or input {actor_output_input!r}"
                )
            peer_id = read_actor_peer_id_from_file(Path(str(actor_output)))
    except (OSError, json.JSONDecodeError, ScenarioError) as exc:
        details = f"Could not determine actor peer ID: {exc}"
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    state.outputs[output_name] = str(peer_id)
    state.recorder.note(f"actor_peer_id={peer_id}")
    details = f"Resolved actor peer ID {peer_id}."
    record_assertion(state.recorder, name, "passed", started_ms, details)
    return ActionOutcome(True, details)


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
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=output_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        state.processes.append(ManagedProcess(process=process, log_handle=output_handle))
        state.recorder.record_capture(label, "command-output", capture_reference(state.recorder, output_path))

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
        state.outputs[output_name] = token
        state.recorder.note(f"bootstrap_target={target}")
        details = f"Client namespace dsh session connected to the actor and echoed token {token}."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    details = f"Client namespace dsh session did not echo token {token}. Capture: {capture_reference(state.recorder, output_path)}"
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def mapped_udp_ports(router_namespace: str) -> list[str]:
    completed = subprocess.run(
        ["ip", "netns", "exec", router_namespace, "nft", "list", "chain", "ip", "miniupnpd", "prerouting"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    return sorted(set(UDP_DPORT_RE.findall(completed.stdout)), key=int)


def run_assert_upnp_udp_mappings(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    router_namespace = require_string(action.get("router_namespace"), field_name="router_namespace", state=state)
    timeout_s = action_timeout_s(action, 20)
    destination = optional_string(action, "capture", state, default="mapped-ports.txt")
    output_name = optional_string(action, "output", state, default="mapped_ports")

    deadline = time.monotonic() + timeout_s
    ports: list[str] = []
    while time.monotonic() <= deadline:
        ports = mapped_udp_ports(router_namespace)
        if ports:
            break
        time.sleep(1)

    output_path = capture_path(state.recorder, destination)
    output_path.write_text("\n".join(ports) + ("\n" if ports else ""), encoding="utf-8")
    state.recorder.record_capture("mapped UDP ports", "command-output", capture_reference(state.recorder, output_path))
    state.outputs[output_name] = ports

    if ports:
        state.recorder.metric("mapped_port_count", len(ports))
        details = "At least one UPnP-mapped UDP port exists while the dhtnet session is active."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    details = "No UPnP-mapped UDP ports were observed while the dhtnet session was active."
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def run_note(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    state.recorder.note(require_string(action.get("message"), field_name="message", state=state))
    return ActionOutcome(True)


def run_field(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    key = require_string(action.get("key"), field_name="key", state=state)
    value = resolve_value(action.get("value"), state)
    state.recorder.field(key, value)
    return ActionOutcome(True)


ACTION_HANDLERS = {
    "assert_namespaces_exist": run_assert_namespaces_exist,
    "assert_upnp_udp_mappings": run_assert_upnp_udp_mappings,
    "capture_command": run_capture_command,
    "capture_file": run_capture_file,
    "dhtnet_dsh_roundtrip": run_dhtnet_dsh_roundtrip,
    "field": run_field,
    "note": run_note,
    "read_actor_peer_id": run_read_actor_peer_id,
}


def run_action(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    kind = action_type(action)
    handler = ACTION_HANDLERS.get(kind)
    if handler is None:
        raise ScenarioError(f"Probe {state.probe.name!r} has unsupported probe_sequence action type {kind!r}")
    name = action_id(action)
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


def write_outputs_file(state: ProbeSequenceState) -> Path | None:
    if not state.probe.outputs_file:
        return None
    output_path = state.recorder.run_dir / state.probe.outputs_file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(state.outputs, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return output_path


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
    )
    recorder = ResultRecorder.from_layout(layout)
    state = ProbeSequenceState(probe=probe, inputs=inputs, context=context, recorder=recorder)
    status = "passed"
    outputs_file: Path | None = None

    recorder.event("run_started", "info", f"Probe {probe.name!r} started")
    for key in ("lab", "topology"):
        value = inputs.get(key)
        if value not in (None, ""):
            recorder.field(key, value)

    try:
        for action in probe.probe_sequence:
            outcome = run_action(action, state)
            if not outcome.success:
                status = "failed"
                if bool(action.get("fatal", True)):
                    break
    except ScenarioError as exc:
        status = "error"
        recorder.event("probe_error", "error", str(exc))
        recorder.note(f"probe_error={exc}")
    except Exception as exc:
        status = "error"
        recorder.event("probe_error", "error", str(exc))
        recorder.note(f"probe_error={exc}")
        raise
    finally:
        cleanup_state(state)
        outputs_file = write_outputs_file(state)
        if outputs_file is not None:
            recorder.record_capture("Probe outputs", "state-dump", str(outputs_file.relative_to(recorder.run_dir)))
        recorder.event("run_finished", status, f"Probe finished with status {status}")
        recorder.finalize(status)

    return ProbeSequenceResult(
        status=status,
        outputs=dict(state.outputs),
        outputs_file=outputs_file,
        summary_json=recorder.run_dir / "summary.json",
        summary_txt=recorder.run_dir / "summary.txt",
    )
