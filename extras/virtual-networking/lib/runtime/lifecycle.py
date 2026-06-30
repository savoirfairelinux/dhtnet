from __future__ import annotations

import os
import pwd
import shlex
import subprocess
from pathlib import Path

from lib.core.models import LaunchUser, ScenarioError
from lib.core.paths import DEFAULT_STATE_ROOT, LIB_DIR, ROOT
from lib.reporting.result_recorder import ResultRecorder
from lib.core.util import now_ms, slugify


def resolve_launch_user() -> LaunchUser:
    if os.environ.get("SUDO_USER"):
        passwd_entry = pwd.getpwnam(os.environ["SUDO_USER"])
    else:
        passwd_entry = pwd.getpwuid(os.getuid())

    env: dict[str, str] = {}
    for key in (
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    ):
        value = os.environ.get(key)
        if value:
            env[key] = value

    xdg_runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if not xdg_runtime_dir:
        candidate = Path(f"/run/user/{passwd_entry.pw_uid}")
        if candidate.is_dir():
            xdg_runtime_dir = str(candidate)
    if xdg_runtime_dir:
        env["XDG_RUNTIME_DIR"] = xdg_runtime_dir

    env["HOME"] = passwd_entry.pw_dir
    env["USER"] = passwd_entry.pw_name
    env["LOGNAME"] = passwd_entry.pw_name
    env["PWD"] = passwd_entry.pw_dir
    env["SHELL"] = passwd_entry.pw_shell or "/bin/sh"
    env["VNET_ROOT"] = os.environ.get("VNET_ROOT", str(ROOT))
    env["VNET_REPO_ROOT"] = os.environ.get("VNET_REPO_ROOT", str(ROOT.parent.parent))
    env["VNET_STATE_ROOT"] = os.environ.get("VNET_STATE_ROOT", str(DEFAULT_STATE_ROOT))
    for key in ("DHTNET_BUILD_DIR", "DHTNET_DNC_BIN", "DHTNET_DSH_BIN", "DHTNET_CRTMGR_BIN", "DHTNET_BOOTSTRAP"):
        value = os.environ.get(key)
        if value:
            env[key] = value

    return LaunchUser(
        username=passwd_entry.pw_name,
        uid=passwd_entry.pw_uid,
        gid=passwd_entry.pw_gid,
        home=passwd_entry.pw_dir,
        shell=passwd_entry.pw_shell or "/bin/sh",
        env=env,
    )


def apply_tree_ownership(path: Path, launch_user: LaunchUser) -> None:
    if not path.exists():
        return
    for root, dirnames, filenames in os.walk(path, topdown=False):
        root_path = Path(root)
        for filename in filenames:
            os.chown(root_path / filename, launch_user.uid, launch_user.gid)
        for dirname in dirnames:
            os.chown(root_path / dirname, launch_user.uid, launch_user.gid)
    os.chown(path, launch_user.uid, launch_user.gid)


def shell_function_command(function_name: str, *args: str) -> list[str]:
    library = shlex.quote(str(LIB_DIR / "shell" / "fixtures.sh"))
    command = " ".join([function_name, *(shlex.quote(arg) for arg in args)])
    return ["bash", "-lc", f"source {library} && {command}"]


def run_command(argv: list[str], capture_path: Path, *, env: dict[str, str] | None = None) -> int:
    command_env = None
    if env is not None:
        command_env = {**os.environ, **env}
    with capture_path.open("w", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(argv)}\n\n")
        try:
            completed = subprocess.run(
                argv,
                stdout=handle,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                env=command_env,
            )
        except OSError as exc:
            handle.write(f"ERROR: {exc}\n")
            return 127
    return completed.returncode


def capture_best_effort(recorder: ResultRecorder, label: str, kind: str, filename: str, argv: list[str]) -> None:
    capture_path = recorder.command_capture_path(filename)
    rc = run_command(argv, capture_path)
    recorder.record_command_capture(label, kind, capture_path)
    if rc != 0:
        recorder.note(f"capture_failed:{filename}:exit_code={rc}")


def copy_named_artifacts(
    recorder: ResultRecorder,
    *,
    artifacts: dict[str, str],
    prefix: str,
    label_prefix: str,
    kind: str = "state-dump",
) -> None:
    for artifact_name, artifact_path in sorted(artifacts.items()):
        source = Path(artifact_path)
        if not source.exists():
            recorder.note(f"artifact_missing:{label_prefix}:{artifact_name}={artifact_path}")
            continue
        destination = f"{prefix}/{slugify(artifact_name)}{source.suffix or '.txt'}"
        try:
            recorder.copy_capture(
                source=source,
                destination=destination,
                label=f"{label_prefix} {artifact_name}",
                kind=kind,
            )
        except ScenarioError as exc:
            recorder.note(f"artifact_copy_failed:{label_prefix}:{artifact_name}={exc}")


def execute_lifecycle_command(
    recorder: ResultRecorder,
    *,
    assertion_name: str,
    event_name: str,
    argv: list[str],
    capture_name: str,
    env: dict[str, str] | None = None,
) -> bool:
    started_ms = now_ms()
    capture_path = recorder.command_capture_path(capture_name)
    recorder.event(event_name, "info", shlex.join(argv))
    rc = run_command(argv, capture_path, env=env)
    capture = recorder.record_command_capture(assertion_name, "command-output", capture_path)
    status = "passed" if rc == 0 else "failed"
    details = f"Command exited {rc}."
    if capture:
        details += f" Capture: {capture}"
    recorder.assertion(
        assertion_name,
        status,
        now_ms() - started_ms,
        details,
    )
    recorder.event(f"{event_name}_finished", status, f"exit_code={rc}")
    return rc == 0


def execute_nonfatal_cleanup(
    recorder: ResultRecorder,
    *,
    argv: list[str],
    capture_name: str,
    env: dict[str, str] | None = None,
) -> None:
    capture_path = recorder.command_capture_path(capture_name)
    recorder.event("pre_cleanup_started", "info", shlex.join(argv))
    rc = run_command(argv, capture_path, env=env)
    recorder.record_command_capture("pre_cleanup_topology", "command-output", capture_path)
    if rc == 0:
        recorder.event("pre_cleanup_finished", "passed", "Pre-cleanup completed")
    else:
        recorder.note(f"pre_cleanup_exit_code={rc}")
        recorder.event("pre_cleanup_finished", "warning", f"Pre-cleanup exited {rc}")
