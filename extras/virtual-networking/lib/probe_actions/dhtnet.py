from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from lib.core.models import ScenarioError
from lib.core.paths import ROOT
from lib.core.util import now_ms
from lib.tools.probe_runner import (
    ActionOutcome,
    ActionSchema,
    ManagedProcess,
    ProbeSequenceState,
    action_id,
    action_number,
    action_timeout_s,
    capture_path,
    optional_string,
    record_assertion,
    register_probe_action,
    require_string,
)


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
    if port == "4222":
        return host
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{host_part}:{port}"


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
    target_peer_id = require_string(action.get("target_peer_id"), field_name="target_peer_id", state=state)
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
            target_peer_id,
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
        details = f"Client namespace dsh session connected to the target and echoed token {token}."
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    capture = state.recorder.record_command_capture(label, "command-output", output_path)
    details = f"Client namespace dsh session did not echo token {token}."
    if capture:
        details += f" Capture: {capture}"
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def register_actions() -> None:
    register_probe_action(
        "dhtnet_dsh_roundtrip",
        ActionSchema(
            required=frozenset({"bootstrap_host", "bootstrap_port", "client_namespace", "target_peer_id"}),
            optional=frozenset({"capture", "label", "output", "startup_delay_s", "timeout_s", "token"}),
        ),
        run_dhtnet_dsh_roundtrip,
    )
