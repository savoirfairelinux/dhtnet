from __future__ import annotations

import json
import os
import shlex
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from lib.loaders.context_loader import actor_context_key, role_context_key, resolve_text, update_context_from_outputs
from .lifecycle import resolve_launch_user
from lib.core.models import ActorSpec, LaunchUser, ManagedActor, ScenarioError, ScenarioSpec, TopologySpec
from lib.reporting.result_recorder import ResultRecorder, RunState
from lib.core.util import slugify


def build_actor_argv(
    namespace: str,
    launch_command: str,
    launch_user: LaunchUser,
    *,
    ready_path: Path | None = None,
    output_path: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    if shutil.which("sudo") is None:
        raise ScenarioError("Managed actor launch requires 'sudo' to be available in PATH")
    if shutil.which("bash") is None:
        raise ScenarioError("Managed actor launch requires 'bash' to be available in PATH")

    env_assignments = [f"{key}={value}" for key, value in launch_user.env.items()]
    if ready_path is not None:
        env_assignments.append(f"VNET_ACTOR_READY_FILE={ready_path}")
    if output_path is not None:
        env_assignments.append(f"VNET_ACTOR_OUTPUT_FILE={output_path}")
    if extra_env:
        env_assignments.extend(f"{key}={value}" for key, value in extra_env.items())
    return [
        "ip",
        "netns",
        "exec",
        namespace,
        "sudo",
        "-u",
        launch_user.username,
        "-H",
        "env",
        *env_assignments,
        "bash",
        "-lc",
        f"exec {launch_command}",
    ]


def actor_log_path(recorder: ResultRecorder, actor_name: str) -> Path:
    actor_slug = slugify(actor_name)
    return recorder.command_capture_path(f"actors/{actor_slug}.log")


def actor_output_path(actor_name: str) -> Path:
    actor_slug = slugify(actor_name)
    return Path(tempfile.gettempdir()) / f"vnet-actor-output-{actor_slug}-{os.getpid()}-{int(time.time() * 1000)}.json"


def prepare_actor_output_path(output_path: Path, launch_user: LaunchUser) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("", encoding="utf-8")
    os.chown(output_path, launch_user.uid, launch_user.gid)
    output_path.chmod(0o600)


def read_actor_outputs(output_path: Path | None) -> dict[str, Any]:
    if output_path is None or not output_path.exists():
        return {}
    payload = output_path.read_text(encoding="utf-8")
    if not payload.strip():
        return {}
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"Actor output file {output_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScenarioError(f"Actor output file {output_path} must contain a JSON object")
    return dict(data)


def launch_actor(
    recorder: ResultRecorder,
    *,
    name: str,
    kind: str,
    namespace: str,
    launch_command: str,
    launch_wait_s: float,
    extra_env: dict[str, str] | None = None,
) -> ManagedActor:
    launch_user = resolve_launch_user()
    ready_path = Path(tempfile.gettempdir()) / f"vnet-actor-ready-{os.getpid()}-{int(time.time() * 1000)}"
    try:
        ready_path.unlink()
    except FileNotFoundError:
        pass
    log_path = actor_log_path(recorder, name)
    output_path = actor_output_path(name)
    log_capture_path = f"captures/{log_path.relative_to(recorder.captures_dir).as_posix()}"
    prepare_actor_output_path(output_path, launch_user)
    argv = build_actor_argv(
        namespace,
        launch_command,
        launch_user,
        ready_path=ready_path,
        output_path=output_path,
        extra_env=extra_env,
    )

    log_handle = log_path.open("w", encoding="utf-8")
    log_handle.write(f"$ {shlex.join(argv)}\n\n")
    log_handle.flush()
    recorder.record_capture(f"Managed actor log ({name})", "log", log_capture_path)
    try:
        process = subprocess.Popen(
            argv,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        log_handle.write(f"ERROR: {exc}\n")
        log_handle.close()
        raise ScenarioError(f"Failed to launch actor command: {exc}") from exc
    actor = ManagedActor(
        name=name,
        kind=kind,
        namespace=namespace,
        launch_command=launch_command,
        user=launch_user,
        process=process,
        log_handle=log_handle,
        log_path=log_path,
        log_capture_path=log_capture_path,
        ready_path=ready_path,
        output_path=output_path,
    )

    if launch_wait_s > 0:
        deadline = time.monotonic() + launch_wait_s
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if ready_path.exists():
                break
            time.sleep(0.25)
    try:
        actor.outputs = read_actor_outputs(output_path)
    except ScenarioError:
        stop_actor(actor, timeout_s=1)
        raise
    return actor


def actor_status(actor: ManagedActor) -> tuple[bool, str]:
    exit_code = actor.process.poll()
    if exit_code is None:
        if actor.ready_path is not None and not actor.ready_path.exists():
            return False, (
                f"Actor is still running in namespace {actor.namespace}, "
                f"but it did not signal readiness. Log: {actor.log_capture_path}"
            )
        return True, (
            f"Actor is now running in namespace {actor.namespace}. "
            f"Log: {actor.log_capture_path}"
        )
    return False, (
        f"Actor exited with code {exit_code} in namespace {actor.namespace}. "
        f"Log: {actor.log_capture_path}"
    )


def actor_launch_status(actor: ManagedActor) -> tuple[bool, str]:
    alive, details = actor_status(actor)
    if not alive:
        return False, details
    if actor.kind == "dsh-listener" and not actor.outputs.get("peer_id"):
        return False, (
            f"Actor is running in namespace {actor.namespace}, but it did not produce "
            f"required output(s): peer_id. Log: {actor.log_capture_path}. "
        )
    return True, details


def cleanup_actor_runtime_files(actor: ManagedActor) -> None:
    if actor.ready_path is not None:
        try:
            actor.ready_path.unlink()
        except FileNotFoundError:
            pass
    if actor.output_path is not None:
        try:
            actor.output_path.unlink()
        except FileNotFoundError:
            pass


def stop_actor(actor: ManagedActor, *, timeout_s: float) -> tuple[str, str]:
    exit_code = actor.process.poll()
    if exit_code is not None:
        actor.log_handle.close()
        cleanup_actor_runtime_files(actor)
        return "passed", (
            f"Actor already exited with code {exit_code}. "
            f"Log: {actor.log_capture_path}"
        )

    try:
        os.killpg(actor.process.pid, signal.SIGTERM)
        actor.process.wait(timeout=timeout_s)
        return "passed", (
            f"Actor stopped with SIGTERM. Log: {actor.log_capture_path}"
        )
    except ProcessLookupError:
        return "passed", (
            f"Actor process group already disappeared. Log: {actor.log_capture_path}"
        )
    except subprocess.TimeoutExpired:
        os.killpg(actor.process.pid, signal.SIGKILL)
        actor.process.wait(timeout=5)
        return "failed", (
            f"Actor required SIGKILL after SIGTERM timeout. "
            f"Log: {actor.log_capture_path}"
        )
    finally:
        actor.log_handle.close()
        cleanup_actor_runtime_files(actor)


def register_actor_outputs(context: dict[str, str], actor: ManagedActor) -> None:
    update_context_from_outputs(
        context,
        actor_context_key(actor.name, ""),
        {
            "namespace": actor.namespace,
            "log_path": actor.log_path,
            **actor.outputs,
        },
    )


def launch_composition_actor(
    recorder: ResultRecorder,
    actor_spec: ActorSpec,
    *,
    scenario: ScenarioSpec,
    topology: TopologySpec,
    context: dict[str, str],
    fixture_payloads: dict[str, dict[str, Any]],
    run_state: RunState,
) -> ManagedActor:
    namespace = context[role_context_key(actor_spec.role, "namespace")]
    extra_env: dict[str, str] = {}
    if actor_spec.kind == "dsh-listener":
        if actor_spec.wait_s > 0:
            extra_env["VNET_ACTOR_READY_TIMEOUT_S"] = str(
                max(1, int(actor_spec.wait_s))
            )
        bootstrap_host = None
        if actor_spec.bootstrap_fixture:
            fixture_payload = fixture_payloads.get(actor_spec.bootstrap_fixture)
            if fixture_payload is None:
                raise ScenarioError(
                    f"Actor {actor_spec.name!r} references unknown bootstrap fixture {actor_spec.bootstrap_fixture!r}"
                )
            bootstrap_host = fixture_payload.get("outputs", {}).get("bootstrap_host")
        if not bootstrap_host:
            raise ScenarioError(f"Actor {actor_spec.name!r} requires a bootstrap fixture with bootstrap_host output")
        launch_command = resolve_text(
            f"{{root}}/actors/launch-dsh-listener.sh --bootstrap {bootstrap_host}",
            context,
            scenario_name=scenario.name,
        )
    else:
        raise ScenarioError(f"Unsupported actor kind {actor_spec.kind!r}")

    actor = launch_actor(
        recorder,
        name=actor_spec.name,
        kind=actor_spec.kind,
        namespace=namespace,
        launch_command=launch_command,
        launch_wait_s=actor_spec.wait_s,
        extra_env=extra_env,
    )
    payload = {
        "name": actor_spec.name,
        "kind": actor_spec.kind,
        "role": actor_spec.role,
        "namespace": namespace,
        "launch_command": launch_command,
        "launch_user": {
            "username": actor.user.username,
            "uid": actor.user.uid,
            "gid": actor.user.gid,
            "home": actor.user.home,
            "shell": actor.user.shell,
        },
        "log_path": str(actor.log_path),
        "outputs": actor.outputs,
    }
    actor.outputs = payload["outputs"]
    run_state.set_actor(actor_spec.name, payload)
    register_actor_outputs(context, actor)
    return actor
