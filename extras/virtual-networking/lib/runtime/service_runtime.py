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

from lib.loaders.context_loader import service_context_key, role_context_key, resolve_text, update_context_from_outputs
from .lifecycle import resolve_launch_user
from lib.core.models import ServiceSpec, LaunchUser, ManagedService, ScenarioError, ScenarioSpec, TopologySpec
from lib.reporting.result_recorder import ResultRecorder, RunState
from lib.core.util import slugify


def build_service_argv(
    namespace: str,
    launch_command: str,
    launch_user: LaunchUser,
    *,
    ready_path: Path | None = None,
    output_path: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    if shutil.which("sudo") is None:
        raise ScenarioError("Managed service launch requires 'sudo' to be available in PATH")
    if shutil.which("bash") is None:
        raise ScenarioError("Managed service launch requires 'bash' to be available in PATH")

    env_assignments = [f"{key}={value}" for key, value in launch_user.env.items()]
    if ready_path is not None:
        env_assignments.append(f"VNET_SERVICE_READY_FILE={ready_path}")
    if output_path is not None:
        env_assignments.append(f"VNET_SERVICE_OUTPUT_FILE={output_path}")
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


def service_log_path(recorder: ResultRecorder, service_name: str) -> Path:
    service_slug = slugify(service_name)
    return recorder.command_capture_path(f"services/{service_slug}.log")


def service_output_path(service_name: str) -> Path:
    service_slug = slugify(service_name)
    return Path(tempfile.gettempdir()) / f"vnet-service-output-{service_slug}-{os.getpid()}-{int(time.time() * 1000)}.json"


def prepare_service_output_path(output_path: Path, launch_user: LaunchUser) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("", encoding="utf-8")
    os.chown(output_path, launch_user.uid, launch_user.gid)
    output_path.chmod(0o600)


def read_service_outputs(output_path: Path | None) -> dict[str, Any]:
    if output_path is None or not output_path.exists():
        return {}
    payload = output_path.read_text(encoding="utf-8")
    if not payload.strip():
        return {}
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"Service output file {output_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScenarioError(f"Service output file {output_path} must contain a JSON object")
    return dict(data)


def launch_service(
    recorder: ResultRecorder,
    *,
    name: str,
    kind: str,
    namespace: str,
    launch_command: str,
    launch_wait_s: float,
    extra_env: dict[str, str] | None = None,
) -> ManagedService:
    launch_user = resolve_launch_user()
    ready_path = Path(tempfile.gettempdir()) / f"vnet-service-ready-{os.getpid()}-{int(time.time() * 1000)}"
    try:
        ready_path.unlink()
    except FileNotFoundError:
        pass
    log_path = service_log_path(recorder, name)
    output_path = service_output_path(name)
    log_capture_path = f"captures/{log_path.relative_to(recorder.captures_dir).as_posix()}"
    prepare_service_output_path(output_path, launch_user)
    argv = build_service_argv(
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
    recorder.record_capture(f"Managed service log ({name})", "log", log_capture_path)
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
        raise ScenarioError(f"Failed to launch service command: {exc}") from exc
    service = ManagedService(
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
        service.outputs = read_service_outputs(output_path)
    except ScenarioError:
        stop_service(service, timeout_s=1)
        raise
    return service


def service_status(service: ManagedService) -> tuple[bool, str]:
    exit_code = service.process.poll()
    if exit_code is None:
        if service.ready_path is not None and not service.ready_path.exists():
            return False, (
                f"Service is still running in namespace {service.namespace}, "
                f"but it did not signal readiness. Log: {service.log_capture_path}"
            )
        return True, (
            f"Service is now running in namespace {service.namespace}. "
            f"Log: {service.log_capture_path}"
        )
    return False, (
        f"Service exited with code {exit_code} in namespace {service.namespace}. "
        f"Log: {service.log_capture_path}"
    )


def service_launch_status(service: ManagedService) -> tuple[bool, str]:
    alive, details = service_status(service)
    if not alive:
        return False, details
    if service.kind == "dsh-listener" and not service.outputs.get("peer_id"):
        return False, (
            f"Service is running in namespace {service.namespace}, but it did not produce "
            f"required output(s): peer_id. Log: {service.log_capture_path}. "
        )
    return True, details


def cleanup_service_runtime_files(service: ManagedService) -> None:
    if service.ready_path is not None:
        try:
            service.ready_path.unlink()
        except FileNotFoundError:
            pass
    if service.output_path is not None:
        try:
            service.output_path.unlink()
        except FileNotFoundError:
            pass


def stop_service(service: ManagedService, *, timeout_s: float) -> tuple[str, str]:
    exit_code = service.process.poll()
    if exit_code is not None:
        service.log_handle.close()
        cleanup_service_runtime_files(service)
        return "passed", (
            f"Service already exited with code {exit_code}. "
            f"Log: {service.log_capture_path}"
        )

    try:
        os.killpg(service.process.pid, signal.SIGTERM)
        service.process.wait(timeout=timeout_s)
        return "passed", (
            f"Service stopped with SIGTERM. Log: {service.log_capture_path}"
        )
    except ProcessLookupError:
        return "passed", (
            f"Service process group already disappeared. Log: {service.log_capture_path}"
        )
    except subprocess.TimeoutExpired:
        os.killpg(service.process.pid, signal.SIGKILL)
        service.process.wait(timeout=5)
        return "failed", (
            f"Service required SIGKILL after SIGTERM timeout. "
            f"Log: {service.log_capture_path}"
        )
    finally:
        service.log_handle.close()
        cleanup_service_runtime_files(service)


def register_service_outputs(context: dict[str, str], service: ManagedService) -> None:
    update_context_from_outputs(
        context,
        service_context_key(service.name, ""),
        {
            "namespace": service.namespace,
            "log_path": service.log_path,
            **service.outputs,
        },
    )


def launch_composition_service(
    recorder: ResultRecorder,
    service_spec: ServiceSpec,
    *,
    scenario: ScenarioSpec,
    topology: TopologySpec,
    context: dict[str, str],
    fixture_payloads: dict[str, dict[str, Any]],
    run_state: RunState,
) -> ManagedService:
    namespace = context[role_context_key(service_spec.role, "namespace")]
    extra_env: dict[str, str] = {}
    if service_spec.kind == "dsh-listener":
        if service_spec.wait_s > 0:
            extra_env["VNET_SERVICE_READY_TIMEOUT_S"] = str(
                max(1, int(service_spec.wait_s))
            )
        bootstrap_host = None
        if service_spec.bootstrap_fixture:
            fixture_payload = fixture_payloads.get(service_spec.bootstrap_fixture)
            if fixture_payload is None:
                raise ScenarioError(
                    f"Service {service_spec.name!r} references unknown bootstrap fixture {service_spec.bootstrap_fixture!r}"
                )
            bootstrap_host = fixture_payload.get("outputs", {}).get("bootstrap_host")
        if not bootstrap_host:
            raise ScenarioError(f"Service {service_spec.name!r} requires a bootstrap fixture with bootstrap_host output")
        launch_command = resolve_text(
            f"{{root}}/lib/service_actions/launch-dsh-listener.sh --bootstrap {bootstrap_host}",
            context,
            scenario_name=scenario.name,
        )
    else:
        raise ScenarioError(f"Unsupported service kind {service_spec.kind!r}")

    service = launch_service(
        recorder,
        name=service_spec.name,
        kind=service_spec.kind,
        namespace=namespace,
        launch_command=launch_command,
        launch_wait_s=service_spec.wait_s,
        extra_env=extra_env,
    )
    payload = {
        "name": service_spec.name,
        "kind": service_spec.kind,
        "role": service_spec.role,
        "namespace": namespace,
        "launch_command": launch_command,
        "launch_user": {
            "username": service.user.username,
            "uid": service.user.uid,
            "gid": service.user.gid,
            "home": service.user.home,
            "shell": service.user.shell,
        },
        "log_path": str(service.log_path),
        "outputs": service.outputs,
    }
    service.outputs = payload["outputs"]
    run_state.set_service(service_spec.name, payload)
    register_service_outputs(context, service)
    return service
