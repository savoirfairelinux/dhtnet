from __future__ import annotations

import shlex
import subprocess
from typing import Any

from lib.core.util import now_ms, slugify
from lib.tools.probe_runner import (
    ActionOutcome,
    ActionSchema,
    ProbeSequenceState,
    action_id,
    capture_path,
    materialize_argv,
    optional_string,
    record_assertion,
    register_probe_action,
)


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


def register_actions() -> None:
    register_probe_action(
        "capture_command",
        ActionSchema(
            required=frozenset({"argv"}),
            optional=frozenset({"destination", "kind", "label"}),
        ),
        run_capture_command,
    )
