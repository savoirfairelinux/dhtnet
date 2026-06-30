from __future__ import annotations

import re
import shlex
import subprocess
import time
from typing import Any

from lib.core.util import now_ms
from lib.tools.probe_runner import (
    ActionOutcome,
    ActionSchema,
    ProbeSequenceState,
    action_id,
    action_timeout_s,
    capture_path,
    optional_string,
    record_assertion,
    register_probe_action,
    require_string,
)

UPNPC_EXTERNAL_IP_RE = re.compile(r"\bExternalIPAddress\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\b")
UPNPC_LOCAL_IP_RE = re.compile(r"\bLocal LAN ip address\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\b")


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


def register_actions() -> None:
    register_probe_action(
        "assert_igd_discovery",
        ActionSchema(
            required=frozenset({"namespace"}),
            optional=frozenset({"capture", "label", "output", "timeout_s"}),
        ),
        run_assert_igd_discovery,
    )
