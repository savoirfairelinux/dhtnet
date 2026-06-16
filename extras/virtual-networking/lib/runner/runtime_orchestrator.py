from __future__ import annotations

import json
import os
import pwd
import re
import shlex
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

from .context_loader import (
    actor_context_key,
    build_scenario_context,
    ensure_role_exists,
    fixture_context_key,
    fixture_record_payload,
    load_fixtures,
    load_probes,
    probe_context_key,
    require_string,
    resolve_text,
    resolve_value,
    resolved_topology_namespaces,
    role_context_key,
    update_context_from_outputs,
    validate_scenario_against_fixtures,
)
from .models import (
    ActorSpec,
    CopyOutputSpec,
    FixtureSpec,
    LaunchUser,
    ManagedActor,
    ProbeSpec,
    ScenarioError,
    ScenarioSpec,
    StepSpec,
    TopologySpec,
)
from .paths import DEFAULT_STATE_ROOT, FIXTURE_DIR, LIB_DIR, PROBE_DIR, ROOT
from .result_recorder import ResultRecorder, RunState
from .cli_printer import print_progress
from .util import ensure_int, now_ms, slugify, strip_cidr


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


def actor_capture_paths(recorder: ResultRecorder, actor_name: str) -> tuple[Path, Path, Path]:
    actor_slug = slugify(actor_name)
    return (
        recorder.command_capture_path(f"actors/{actor_slug}.log"),
        recorder.command_capture_path(f"actors/{actor_slug}-meta.txt"),
        recorder.command_capture_path(f"actors/{actor_slug}-output.json"),
    )


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
    import json

    data = json.loads(payload)
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
    log_path, meta_path, output_path = actor_capture_paths(recorder, name)
    log_capture_path = f"captures/{log_path.relative_to(recorder.captures_dir).as_posix()}"
    meta_capture_path = f"captures/{meta_path.relative_to(recorder.captures_dir).as_posix()}"
    output_capture_path = f"captures/{output_path.relative_to(recorder.captures_dir).as_posix()}"
    prepare_actor_output_path(output_path, launch_user)
    argv = build_actor_argv(
        namespace,
        launch_command,
        launch_user,
        ready_path=ready_path,
        output_path=output_path,
        extra_env=extra_env,
    )

    meta_lines = [
        f"name={name}",
        f"kind={kind}",
        f"namespace={namespace}",
        f"username={launch_user.username}",
        f"uid={launch_user.uid}",
        f"gid={launch_user.gid}",
        f"home={launch_user.home}",
        f"shell={launch_user.shell}",
        f"launch_wait_s={launch_wait_s}",
        f"launch_command={launch_command}",
        f"argv={shlex.join(argv)}",
        f"output_path={output_path}",
    ]
    meta_path.write_text("\n".join(meta_lines) + "\n", encoding="utf-8")
    recorder.record_capture(f"Managed actor metadata ({name})", "state-dump", meta_capture_path)

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
        meta_path=meta_path,
        log_capture_path=log_capture_path,
        meta_capture_path=meta_capture_path,
        ready_path=ready_path,
        output_path=output_path,
        output_capture_path=output_capture_path,
    )

    if launch_wait_s > 0:
        deadline = time.monotonic() + launch_wait_s
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if ready_path.exists():
                break
            time.sleep(0.25)
    actor.outputs = read_actor_outputs(output_path)
    if output_path.exists():
        recorder.record_capture(f"Managed actor output ({name})", "state-dump", output_capture_path)
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
        output_details = actor.output_capture_path or str(actor.output_path)
        return False, (
            f"Actor is running in namespace {actor.namespace}, but it did not produce "
            f"required output(s): peer_id. Log: {actor.log_capture_path}. "
            f"Output: {output_details}"
        )
    return True, details


def stop_actor(actor: ManagedActor, *, timeout_s: float) -> tuple[str, str]:
    exit_code = actor.process.poll()
    if exit_code is not None:
        actor.log_handle.close()
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
        if actor.ready_path is not None:
            try:
                actor.ready_path.unlink()
            except FileNotFoundError:
                pass


def shell_function_command(function_name: str, *args: str) -> list[str]:
    library = shlex.quote(str(LIB_DIR / "fixtures.sh"))
    command = " ".join([function_name, *(shlex.quote(arg) for arg in args)])
    return ["bash", "-lc", f"source {library} && {command}"]


def run_command(argv: list[str], capture_path: Path) -> int:
    with capture_path.open("w", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(argv)}\n\n")
        try:
            completed = subprocess.run(argv, stdout=handle, stderr=subprocess.STDOUT, text=True, check=False)
        except OSError as exc:
            handle.write(f"ERROR: {exc}\n")
            return 127
    return completed.returncode


def capture_best_effort(recorder: ResultRecorder, label: str, kind: str, filename: str, argv: list[str]) -> None:
    capture_path = recorder.command_capture_path(filename)
    rc = run_command(argv, capture_path)
    recorder.record_capture(label, kind, f"captures/{filename}")
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


def setup_topology(recorder: ResultRecorder, topology: TopologySpec) -> bool:
    return execute_lifecycle_command(
        recorder,
        assertion_name="setup_topology",
        event_name="setup_started",
        argv=shell_function_command("vnet_fixture_apply_topology", str(topology.path)),
        capture_name="setup.txt",
    )


def preclean_topology(recorder: ResultRecorder, topology: TopologySpec) -> None:
    execute_nonfatal_cleanup(
        recorder,
        argv=shell_function_command("vnet_fixture_delete_topology_namespaces", str(topology.path)),
        capture_name="pre-cleanup.txt",
    )


def teardown_topology(recorder: ResultRecorder, topology: TopologySpec) -> bool:
    return execute_lifecycle_command(
        recorder,
        assertion_name="teardown_topology",
        event_name="teardown_started",
        argv=shell_function_command("vnet_fixture_delete_topology_namespaces", str(topology.path)),
        capture_name="teardown.txt",
    )


def setup_fixture(
    recorder: ResultRecorder,
    fixture: FixtureSpec,
    *,
    scenario: ScenarioSpec,
    topology: TopologySpec,
    context: dict[str, str],
    run_state: RunState,
) -> dict[str, Any]:
    options = resolve_value(fixture.options, context, scenario_name=scenario.name)
    outputs: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    capture_name = f"fixtures/{slugify(fixture.name)}-up.txt"
    capture_path = recorder.command_capture_path(capture_name)

    if fixture.kind == "local-bootstrap":
        role_name = ensure_role_exists(
            require_string(options.get("role"), field_name="fixture.options.role", scenario_path=fixture.path or scenario.path),
            topology=topology,
            object_path=fixture.path or scenario.path,
            field_name=f"fixture {fixture.name!r}.options.role",
        )
        namespace = context[role_context_key(role_name, "namespace")]
        bind_ip = strip_cidr(require_string(options.get("bind_ip"), field_name="fixture.options.bind_ip", scenario_path=fixture.path or scenario.path))
        port = ensure_int(options.get("port", 4222), field_name=f"fixture {fixture.name!r}.options.port")
        timeout_s = ensure_int(options.get("timeout_s", 10), field_name=f"fixture {fixture.name!r}.options.timeout_s")
        bootstrap_script = require_string(
            options.get("bootstrap_script"),
            field_name="fixture.options.bootstrap_script",
            scenario_path=fixture.path or scenario.path,
        )
        pidfile = require_string(options.get("pidfile"), field_name="fixture.options.pidfile", scenario_path=fixture.path or scenario.path)
        logfile = require_string(options.get("logfile"), field_name="fixture.options.logfile", scenario_path=fixture.path or scenario.path)
        rc = run_command(
            shell_function_command(
                "vnet_fixture_start_local_bootstrap",
                namespace,
                bind_ip,
                str(port),
                pidfile,
                logfile,
                str(timeout_s),
                bootstrap_script,
            ),
            capture_path,
        )
        recorder.record_capture(f"Fixture setup ({fixture.name})", "command-output", f"captures/{capture_name}")
        if rc != 0:
            raise ScenarioError(f"Fixture {fixture.name!r} failed to start local bootstrap. Capture: captures/{capture_name}")
        outputs = {
            "role": role_name,
            "namespace": namespace,
            "bootstrap_host": bind_ip,
            "bootstrap_port": port,
            "bootstrap_endpoint": f"{bind_ip}:{port}",
        }
        artifacts = {"pidfile": pidfile, "logfile": logfile}
    elif fixture.kind == "miniupnpd":
        role_name = ensure_role_exists(
            require_string(options.get("role"), field_name="fixture.options.role", scenario_path=fixture.path or scenario.path),
            topology=topology,
            object_path=fixture.path or scenario.path,
            field_name=f"fixture {fixture.name!r}.options.role",
        )
        namespace = context[role_context_key(role_name, "namespace")]
        pidfile = require_string(options.get("pidfile"), field_name="fixture.options.pidfile", scenario_path=fixture.path or scenario.path)
        logfile = require_string(options.get("logfile"), field_name="fixture.options.logfile", scenario_path=fixture.path or scenario.path)
        configfile = require_string(options.get("configfile"), field_name="fixture.options.configfile", scenario_path=fixture.path or scenario.path)
        ext_iface = require_string(options.get("ext_iface"), field_name="fixture.options.ext_iface", scenario_path=fixture.path or scenario.path)
        listen_iface = require_string(options.get("listen_iface"), field_name="fixture.options.listen_iface", scenario_path=fixture.path or scenario.path)
        uuid = require_string(options.get("uuid"), field_name="fixture.options.uuid", scenario_path=fixture.path or scenario.path)
        friendly_name = require_string(
            options.get("friendly_name"),
            field_name="fixture.options.friendly_name",
            scenario_path=fixture.path or scenario.path,
        )
        ext_ip = require_string(options.get("ext_ip"), field_name="fixture.options.ext_ip", scenario_path=fixture.path or scenario.path)
        rc = run_command(
            shell_function_command(
                "vnet_fixture_start_miniupnpd_instance",
                namespace,
                configfile,
                pidfile,
                logfile,
                ext_iface,
                listen_iface,
                uuid,
                friendly_name,
                ext_ip,
            ),
            capture_path,
        )
        recorder.record_capture(f"Fixture setup ({fixture.name})", "command-output", f"captures/{capture_name}")
        if rc != 0:
            raise ScenarioError(f"Fixture {fixture.name!r} failed to start miniupnpd. Capture: captures/{capture_name}")

        discovery_role = options.get("discovery_role")
        discovery_log = options.get("discovery_log")
        if isinstance(discovery_role, str) and discovery_role and isinstance(discovery_log, str) and discovery_log:
            discovery_role = ensure_role_exists(
                discovery_role,
                topology=topology,
                object_path=fixture.path or scenario.path,
                field_name=f"fixture {fixture.name!r}.options.discovery_role",
            )
            discovery_namespace = context[role_context_key(discovery_role, "namespace")]
            discovery_timeout_s = ensure_int(
                options.get("discovery_timeout_s", 10),
                field_name=f"fixture {fixture.name!r}.options.discovery_timeout_s",
            )
            discovery_capture_name = f"fixtures/{slugify(fixture.name)}-discovery.txt"
            discovery_capture_path = recorder.command_capture_path(discovery_capture_name)
            discovery_rc = run_command(
                shell_function_command(
                    "vnet_fixture_wait_for_discovery",
                    discovery_namespace,
                    discovery_log,
                    str(discovery_timeout_s),
                ),
                discovery_capture_path,
            )
            recorder.record_capture(
                f"Fixture discovery wait ({fixture.name})",
                "command-output",
                f"captures/{discovery_capture_name}",
            )
            if discovery_rc != 0:
                recorder.note(f"fixture_discovery_timeout:{fixture.name}")
            outputs["discovery_role"] = discovery_role
            outputs["discovery_namespace"] = discovery_namespace
            artifacts["discovery_log"] = discovery_log

        outputs.update({"role": role_name, "namespace": namespace, "external_ip": ext_ip})
        artifacts.update({"pidfile": pidfile, "logfile": logfile, "configfile": configfile})
    else:
        raise ScenarioError(f"Unsupported fixture kind {fixture.kind!r}")

    payload = fixture_record_payload(fixture, outputs, artifacts, options)
    run_state.set_fixture(fixture.name, payload)
    update_context_from_outputs(context, fixture_context_key(fixture.name, ""), outputs)
    return payload


def stop_fixture(
    recorder: ResultRecorder,
    fixture_payload: dict[str, Any],
) -> tuple[str, str]:
    fixture_name = str(fixture_payload["name"])
    artifacts = fixture_payload.get("artifacts", {})
    pidfile = artifacts.get("pidfile")
    if not isinstance(pidfile, str) or not pidfile:
        return "passed", f"Fixture {fixture_name} has no pidfile to stop."
    capture_name = f"fixtures/{slugify(fixture_name)}-down.txt"
    capture_path = recorder.command_capture_path(capture_name)
    rc = run_command(shell_function_command("vnet_fixture_stop_pidfile", pidfile), capture_path)
    recorder.record_capture(f"Fixture teardown ({fixture_name})", "command-output", f"captures/{capture_name}")
    status = "passed" if rc == 0 else "failed"
    details = f"Fixture {fixture_name} stop command exited {rc}. Capture: captures/{capture_name}"
    return status, details


def copy_fixture_artifacts(recorder: ResultRecorder, fixture_payloads: dict[str, dict[str, Any]]) -> None:
    for fixture_name, payload in sorted(fixture_payloads.items()):
        artifacts = payload.get("artifacts", {})
        if isinstance(artifacts, dict):
            copy_named_artifacts(
                recorder,
                artifacts={str(key): str(value) for key, value in artifacts.items()},
                prefix=f"fixtures/{slugify(fixture_name)}",
                label_prefix=f"Fixture artifact ({fixture_name})",
            )


def register_actor_outputs(context: dict[str, str], actor: ManagedActor) -> None:
    update_context_from_outputs(
        context,
        actor_context_key(actor.name, ""),
        {
            "namespace": actor.namespace,
            "log_path": actor.log_path,
            "meta_path": actor.meta_path,
            "output_path": actor.output_path,
            **actor.outputs,
        },
    )


EXACT_PLACEHOLDER_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def register_probe_outputs(context: dict[str, str], step_name: str, payload: dict[str, Any]) -> None:
    propagated: dict[str, Any] = {
        "status": payload.get("status", ""),
        "result_dir": payload.get("result_dir", ""),
    }
    for key in ("outputs_file", "summary_json", "summary_txt"):
        value = payload.get(key)
        if value:
            propagated[key] = value
    outputs = payload.get("outputs", {})
    if isinstance(outputs, dict):
        propagated.update(outputs)
    update_context_from_outputs(context, probe_context_key(step_name, ""), propagated)


def build_probe_local_context(
    recorder: ResultRecorder,
    step: StepSpec,
    context: dict[str, str],
) -> tuple[dict[str, str], Path]:
    probe_slug = slugify(step.name)
    probe_run_id = f"{context['run_id']}-{probe_slug}"
    probe_result_dir = recorder.run_dir / "probes" / probe_slug
    probe_result_dir.mkdir(parents=True, exist_ok=True)
    local_context = dict(context)
    local_context["probe_run_id"] = probe_run_id
    local_context["PROBE_RUN_ID"] = probe_run_id
    local_context["probe_result_dir"] = str(probe_result_dir)
    local_context["PROBE_RESULT_DIR"] = str(probe_result_dir)
    return local_context, probe_result_dir


def resolve_probe_binding(
    binding: Any,
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
    binding_path: str,
) -> Any:
    if isinstance(binding, str):
        return resolve_text(binding, context, scenario_name=scenario.name)
    if isinstance(binding, list):
        return [
            resolve_probe_binding(item, context, scenario=scenario, binding_path=f"{binding_path}[{index}]")
            for index, item in enumerate(binding)
        ]
    if not isinstance(binding, dict):
        return binding

    source_keys = [key for key in ("role", "actor", "fixture", "prior_step", "context", "value") if key in binding]
    if len(source_keys) > 1:
        raise ScenarioError(
            f"Scenario {scenario.name!r} binding {binding_path!r} must reference exactly one source, got {source_keys}"
        )
    if "value" in binding:
        return resolve_probe_binding(binding["value"], context, scenario=scenario, binding_path=f"{binding_path}.value")
    if "role" in binding:
        role_name = require_string(binding["role"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field", "namespace")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding a role")
        context_key = role_context_key(role_name, field_name)
    elif "actor" in binding:
        actor_name = require_string(binding["actor"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field", "namespace")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding an actor")
        context_key = actor_context_key(actor_name, field_name)
    elif "fixture" in binding:
        fixture_name = require_string(binding["fixture"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding a fixture")
        context_key = fixture_context_key(fixture_name, field_name)
    elif "prior_step" in binding:
        step_name = require_string(binding["prior_step"], field_name=binding_path, scenario_path=scenario.path)
        field_name = binding.get("field")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {binding_path}.field must be a non-empty string when binding a prior_step")
        context_key = probe_context_key(step_name, field_name)
    elif "context" in binding:
        context_key = require_string(binding["context"], field_name=binding_path, scenario_path=scenario.path)
    else:
        return {
            key: resolve_probe_binding(value, context, scenario=scenario, binding_path=f"{binding_path}.{key}")
            for key, value in binding.items()
        }

    if context_key not in context:
        raise ScenarioError(
            f"Scenario {scenario.name!r} binding {binding_path!r} references unavailable context key {context_key!r}"
        )
    return context[context_key]


def resolve_probe_inputs(step: StepSpec, context: dict[str, str], *, scenario: ScenarioSpec) -> dict[str, Any]:
    return {
        input_name: resolve_probe_binding(binding, context, scenario=scenario, binding_path=f"step {step.name}.inputs.{input_name}")
        for input_name, binding in step.inputs.items()
    }


def build_default_probe_inputs(
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
) -> dict[str, Any]:
    return {
        "run_id": context["probe_run_id"],
        "result_dir": context["probe_result_dir"],
        "artifact_root": context["artifact_root"],
        "lab": scenario.lab,
        "topology": scenario.topology,
        "scenario": scenario.name,
    }


def add_scalar_probe_inputs_to_context(context: dict[str, str], inputs: dict[str, Any]) -> dict[str, str]:
    merged = dict(context)
    for key, value in inputs.items():
        if value is None:
            continue
        if isinstance(value, bool):
            merged[key] = "1" if value else "0"
        elif isinstance(value, (str, int, float)):
            merged[key] = str(value)
    return merged


def materialize_probe_template_argv(
    argv_template: Sequence[str],
    *,
    context: dict[str, str],
    inputs: dict[str, Any],
    scenario: ScenarioSpec,
) -> list[str]:
    materialized: list[str] = []
    merged_context = add_scalar_probe_inputs_to_context(context, inputs)
    for item in argv_template:
        placeholder_match = EXACT_PLACEHOLDER_RE.match(item)
        if placeholder_match:
            key = placeholder_match.group(1)
            if key in inputs:
                value = inputs[key]
            elif key in merged_context:
                value = merged_context[key]
            else:
                raise ScenarioError(f"Scenario {scenario.name!r} probe template references unknown input {key!r}")
            if isinstance(value, list):
                materialized.extend(str(part) for part in value)
            elif value is None:
                continue
            elif isinstance(value, dict):
                raise ScenarioError(f"Scenario {scenario.name!r} probe template cannot expand object input {key!r} into argv")
            else:
                materialized.append(str(value))
            continue
        materialized.append(resolve_text(item, merged_context, scenario_name=scenario.name))
    return materialized


def build_probe_command(
    probe: ProbeSpec,
    inputs: dict[str, Any],
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
) -> list[str]:
    if probe.backend == "command":
        return materialize_probe_template_argv(probe.argv, context=context, inputs=inputs, scenario=scenario)
    if probe.backend == "namespace-command":
        namespace_input = probe.namespace_input or "namespace"
        argv_input = probe.argv_input or "argv"
        namespace = inputs.get(namespace_input)
        argv_value = inputs.get(argv_input)
        if not isinstance(namespace, str) or not namespace:
            raise ScenarioError(f"Scenario {scenario.name!r} probe {probe.name!r} requires string input {namespace_input!r}")
        if not isinstance(argv_value, list) or not all(isinstance(item, str) for item in argv_value):
            raise ScenarioError(f"Scenario {scenario.name!r} probe {probe.name!r} requires string-list input {argv_input!r}")
        return ["ip", "netns", "exec", namespace, *argv_value]
    if probe.backend == "flag-command":
        command = materialize_probe_template_argv(probe.argv_prefix, context=context, inputs=inputs, scenario=scenario)
        for input_name in probe.flag_order:
            if input_name not in inputs:
                continue
            value = inputs[input_name]
            if value is None or value == "" or value == []:
                continue
            command.append(f"--{input_name.replace('_', '-')}")
            if isinstance(value, list):
                command.extend(str(item) for item in value)
            else:
                command.append(str(value))
        return command
    raise ScenarioError(f"Unsupported probe backend {probe.backend!r}")


def read_probe_outputs(
    probe: ProbeSpec,
    result_dir: Path,
) -> tuple[dict[str, Any], str, str, str]:
    outputs: dict[str, Any] = {}
    outputs_file = ""
    summary_json = result_dir / "summary.json"
    summary_txt = result_dir / "summary.txt"

    if probe.outputs_file:
        output_path = result_dir / probe.outputs_file
        if output_path.exists():
            data = json.loads(output_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ScenarioError(f"Probe outputs file must contain a JSON object: {output_path}")
            outputs.update(data)
            outputs_file = str(output_path)

    if summary_json.exists():
        summary = json.loads(summary_json.read_text(encoding="utf-8"))
        if not isinstance(summary, dict):
            raise ScenarioError(f"Probe summary file must contain a JSON object: {summary_json}")
        summary_status = summary.get("status")
        if summary_status is not None and "status" not in outputs:
            outputs["status"] = summary_status
        metrics = summary.get("metrics")
        if isinstance(metrics, dict):
            for key, value in metrics.items():
                outputs.setdefault(key, value)

    return outputs, outputs_file, str(summary_json) if summary_json.exists() else "", str(summary_txt) if summary_txt.exists() else ""


def merged_probe_copy_outputs(probe: ProbeSpec, step: StepSpec) -> list[CopyOutputSpec]:
    return [*probe.default_copy_outputs, *step.copy_outputs]


def record_skipped_steps(
    recorder: ResultRecorder,
    steps: Sequence[StepSpec],
    *,
    reason: str,
) -> None:
    for step in steps:
        recorder.assertion(step.name, "skipped", 0, reason)
        recorder.event("step_skipped", "skipped", f"{step.name}: {reason}")


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
        "log_path": str(actor.log_path),
        "meta_path": str(actor.meta_path),
        "output_path": str(actor.output_path) if actor.output_path else "",
        "outputs": actor.outputs,
    }
    actor.outputs = payload["outputs"]
    run_state.set_actor(actor_spec.name, payload)
    register_actor_outputs(context, actor)
    return actor


def execute_probe_step(
    recorder: ResultRecorder,
    step: StepSpec,
    context: dict[str, str],
    *,
    scenario: ScenarioSpec,
    probes: dict[str, ProbeSpec],
    run_state: RunState,
) -> bool:
    if step.probe is None:
        raise ScenarioError(f"Scenario {scenario.name!r} step {step.name!r} is missing a probe name")
    probe = probes.get(step.probe)
    if probe is None:
        raise ScenarioError(f"Scenario {scenario.name!r} step {step.name!r} references unknown probe {step.probe!r}")

    local_context, probe_result_dir = build_probe_local_context(recorder, step, context)
    resolved_inputs = resolve_probe_inputs(step, local_context, scenario=scenario)
    probe_inputs = {**build_default_probe_inputs(local_context, scenario=scenario), **resolved_inputs}

    missing_inputs = [
        input_name
        for input_name in probe.required_inputs
        if input_name not in probe_inputs or probe_inputs[input_name] is None or probe_inputs[input_name] == ""
    ]
    if missing_inputs:
        raise ScenarioError(
            f"Scenario {scenario.name!r} step {step.name!r} is missing required probe inputs for {probe.name!r}: {', '.join(missing_inputs)}"
        )

    command_context = add_scalar_probe_inputs_to_context(local_context, probe_inputs)
    command = build_probe_command(probe, probe_inputs, command_context, scenario=scenario)
    success, status = execute_materialized_step(
        recorder,
        step,
        command,
        command_context,
        scenario_name=scenario.name,
        capture_name=step.capture or probe.default_capture,
        label=step.label or probe.default_label,
        kind=step.kind or probe.default_kind,
        copy_outputs=merged_probe_copy_outputs(probe, step),
    )

    outputs, outputs_file, summary_json, summary_txt = read_probe_outputs(probe, probe_result_dir)
    probe_payload = {
        "name": step.name,
        "probe": probe.name,
        "backend": probe.backend,
        "status": status,
        "result_dir": str(probe_result_dir),
        "inputs": probe_inputs,
        "outputs_file": outputs_file,
        "summary_json": summary_json,
        "summary_txt": summary_txt,
        "outputs": outputs,
    }
    run_state.set_probe(step.name, probe_payload)
    register_probe_outputs(context, step.name, probe_payload)
    return success


def collect_namespace_snapshots(recorder: ResultRecorder, context: dict[str, str], phase: str) -> None:
    capture_best_effort(recorder, f"{phase} namespace list", "state-dump", f"{phase}-netns-list.txt", ["ip", "netns", "list"])

    namespaces: dict[str, str] = {}
    for key, value in context.items():
        if key.endswith("_NS") and value:
            namespaces.setdefault(value, key)

    recorder.metric("namespace_count", len(namespaces))
    for namespace in sorted(namespaces):
        ns_slug = slugify(namespace)
        capture_best_effort(
            recorder,
            f"{phase} {namespace} addresses",
            "state-dump",
            f"{phase}-{ns_slug}-addr.txt",
            ["ip", "-n", namespace, "addr", "show"],
        )
        capture_best_effort(
            recorder,
            f"{phase} {namespace} routes",
            "state-dump",
            f"{phase}-{ns_slug}-route.txt",
            ["ip", "-n", namespace, "route", "show"],
        )


def execute_lifecycle_command(
    recorder: ResultRecorder,
    *,
    assertion_name: str,
    event_name: str,
    argv: list[str],
    capture_name: str,
) -> bool:
    started_ms = now_ms()
    capture_path = recorder.command_capture_path(capture_name)
    recorder.event(event_name, "info", shlex.join(argv))
    rc = run_command(argv, capture_path)
    recorder.record_capture(assertion_name, "command-output", f"captures/{capture_name}")
    status = "passed" if rc == 0 else "failed"
    recorder.assertion(
        assertion_name,
        status,
        now_ms() - started_ms,
        f"Command exited {rc}. Capture: captures/{capture_name}",
    )
    recorder.event(f"{event_name}_finished", status, f"exit_code={rc}")
    return rc == 0


def execute_nonfatal_cleanup(
    recorder: ResultRecorder,
    *,
    argv: list[str],
    capture_name: str,
) -> None:
    capture_path = recorder.command_capture_path(capture_name)
    recorder.event("pre_cleanup_started", "info", shlex.join(argv))
    rc = run_command(argv, capture_path)
    recorder.record_capture("pre_cleanup_topology", "command-output", f"captures/{capture_name}")
    if rc == 0:
        recorder.event("pre_cleanup_finished", "passed", "Pre-cleanup completed")
    else:
        recorder.note(f"pre_cleanup_exit_code={rc}")
        recorder.event("pre_cleanup_finished", "warning", f"Pre-cleanup exited {rc}")


def execute_materialized_step(
    recorder: ResultRecorder,
    step: StepSpec,
    command: list[str],
    context: dict[str, str],
    *,
    scenario_name: str,
    capture_name: str | None = None,
    label: str | None = None,
    kind: str | None = None,
    copy_outputs: Sequence[CopyOutputSpec] | None = None,
) -> tuple[bool, str]:
    capture_name = capture_name or step.capture or f"{slugify(step.name)}.txt"
    capture_path = recorder.command_capture_path(capture_name)
    capture_label = label or step.label or step.name
    capture_kind = kind or step.kind or "command-output"
    effective_copy_outputs = list(copy_outputs if copy_outputs is not None else step.copy_outputs)

    started_ms = now_ms()
    recorder.event("step_started", "info", f"{step.name}: {shlex.join(command)}")
    rc = run_command(command, capture_path)
    recorder.record_capture(capture_label, capture_kind, f"captures/{capture_name}")

    details = [f"Command exited {rc}.", f"Capture: captures/{capture_name}"]
    copy_failed = False
    for copy_output in effective_copy_outputs:
        source = Path(resolve_text(copy_output.source, context, scenario_name=scenario_name))
        destination = resolve_text(copy_output.destination, context, scenario_name=scenario_name)
        if rc != 0 and not source.exists():
            continue
        try:
            recorder.copy_capture(
                source=source,
                destination=destination,
                label=copy_output.label,
                kind=copy_output.kind,
            )
        except ScenarioError as exc:
            copy_failed = True
            details.append(str(exc))

    if rc != 0 or copy_failed:
        status = "failed"
        success = step.allow_failure
    else:
        status = "passed"
        success = True

    recorder.assertion(step.name, status, now_ms() - started_ms, " ".join(details))
    recorder.event("step_finished", status, f"{step.name}: exit_code={rc}")
    return success, status


def run_scenario(
    scenario: ScenarioSpec,
    *,
    artifact_root: Path,
    run_id: str,
    keep_topology: bool,
    actor_stop_timeout_s: float,
) -> int:
    if os.geteuid() != 0:
        raise ScenarioError("run requires root privileges")
    if actor_stop_timeout_s <= 0:
        raise ScenarioError("--actor-stop-timeout-s must be greater than zero")

    artifact_root.mkdir(parents=True, exist_ok=True)
    DEFAULT_STATE_ROOT.mkdir(parents=True, exist_ok=True)
    artifact_owner = resolve_launch_user()
    recorder = ResultRecorder(run_id=run_id, scenario=scenario.name, artifact_root=artifact_root)
    run_state = RunState(recorder.run_state_path, run_id=run_id, scenario=scenario.name, lab=scenario.lab)
    topology, context = build_scenario_context(
        scenario,
        artifact_root=artifact_root,
        run_id=run_id,
    )
    fixtures_registry = load_fixtures(FIXTURE_DIR)
    probe_registry = load_probes(PROBE_DIR)
    validate_scenario_against_fixtures(scenario, topology, fixtures_registry, probe_registry)
    context["run_dir"] = str(recorder.run_dir)
    context["RUN_DIR"] = str(recorder.run_dir)
    lab_root = Path(tempfile.mkdtemp(prefix=f"{slugify(scenario.lab)}.", dir=str(DEFAULT_STATE_ROOT)))
    context["lab_root"] = str(lab_root)
    context["LAB_ROOT"] = str(lab_root)
    run_state.set_topology(topology)
    run_state.set_context(context)
    status = "passed"
    setup_ok = False
    should_exit = False
    skip_reason: str | None = None
    next_step_index = 0
    actors: dict[str, ManagedActor] = {}
    fixture_payloads: dict[str, dict[str, Any]] = {}

    recorder.field("lab", scenario.lab)
    recorder.field("topology", scenario.topology)
    recorder.field("scenario_file", str(scenario.path.relative_to(ROOT)))
    recorder.field("topology_file", str(topology.path.relative_to(ROOT)))
    for key, value in scenario.fields.items():
        recorder.field(key, value)
    for note in scenario.notes:
        recorder.note(note)

    recorder.copy_capture(
        source=scenario.path,
        destination="scenario.json",
        label="Scenario definition",
        kind="scenario-definition",
    )
    recorder.copy_capture(
        source=topology.path,
        destination="topology.json",
        label="Topology definition",
        kind="scenario-definition",
    )
    for fixture_name in scenario.fixtures:
        fixture = fixtures_registry[fixture_name]
        if fixture.path is not None:
            recorder.copy_capture(
                source=fixture.path,
                destination=f"fixtures/{slugify(fixture_name)}.json",
                label=f"Fixture definition ({fixture_name})",
                kind="scenario-definition",
            )
    recorder.event("run_started", "info", f"Scenario {scenario.name!r} started")
    print_progress(f"Scenario {scenario.name} (run-id: {run_id})")

    try:
        print_progress("Pre-cleaning topology")
        preclean_topology(recorder, topology)
        print_progress("Setting up topology")
        setup_ok = setup_topology(recorder, topology)
        if not setup_ok:
            status = "failed"
            should_exit = True
            skip_reason = "Skipped because topology setup failed."

        if not should_exit:
            recorder.assertion(
                "topology_context_ready",
                "passed",
                0,
                f"Resolved namespaces: {', '.join(resolved_topology_namespaces(topology, context, scenario_name=scenario.name))}.",
            )
            collect_namespace_snapshots(recorder, context, "setup")

        if not should_exit:
            for fixture_name in scenario.fixtures:
                print_progress(f"Setting up fixture {fixture_name}")
                started_ms = now_ms()
                try:
                    fixture_payload = setup_fixture(
                        recorder,
                        fixtures_registry[fixture_name],
                        scenario=scenario,
                        topology=topology,
                        context=context,
                        run_state=run_state,
                    )
                except ScenarioError as exc:
                    recorder.assertion(
                        f"fixture_{slugify(fixture_name)}_ready",
                        "failed",
                        now_ms() - started_ms,
                        str(exc),
                    )
                    status = "failed"
                    should_exit = True
                    skip_reason = f"Skipped because fixture {fixture_name} failed to start."
                    break
                fixture_payloads[fixture_name] = fixture_payload
                run_state.set_context(context)
                recorder.assertion(
                    f"fixture_{slugify(fixture_name)}_ready",
                    "passed",
                    now_ms() - started_ms,
                    f"Fixture {fixture_name} started.",
                )

        if not should_exit:
            for actor_spec in scenario.actors:
                started_ms = now_ms()
                print_progress(f"Launching actor {actor_spec.name} in role {actor_spec.role}")
                try:
                    actor = launch_composition_actor(
                        recorder,
                        actor_spec,
                        scenario=scenario,
                        topology=topology,
                        context=context,
                        fixture_payloads=fixture_payloads,
                        run_state=run_state,
                    )
                except ScenarioError as exc:
                    recorder.assertion(
                        f"launch_actor_{slugify(actor_spec.name)}",
                        "failed",
                        now_ms() - started_ms,
                        str(exc),
                    )
                    status = "failed"
                    should_exit = True
                    skip_reason = f"Skipped because actor {actor_spec.name} failed to launch."
                    break
                actors[actor_spec.name] = actor
                run_state.set_context(context)
                recorder.field(actor_context_key(actor_spec.name, "namespace"), actor.namespace)
                recorder.note(f"launch_user:{actor_spec.name}={actor.user.username}")
                recorder.note(f"launch_home:{actor_spec.name}={actor.user.home}")
                alive, details = actor_launch_status(actor)
                recorder.assertion(
                    f"launch_actor_{slugify(actor_spec.name)}",
                    "passed" if alive else "failed",
                    now_ms() - started_ms,
                    details,
                )
                if not alive:
                    status = "failed"
                    should_exit = True
                    skip_reason = f"Skipped because actor {actor_spec.name} did not become ready."
                    break

        if not should_exit:
            for index, step in enumerate(scenario.steps, start=1):
                next_step_index = index
                print_progress(f"Step {index}/{len(scenario.steps)}: {step.name}")
                started_ms = now_ms()
                try:
                    success = execute_probe_step(
                        recorder,
                        step,
                        context,
                        scenario=scenario,
                        probes=probe_registry,
                        run_state=run_state,
                    )
                except ScenarioError as exc:
                    recorder.assertion(step.name, "failed", now_ms() - started_ms, str(exc))
                    status = "failed"
                    skip_reason = f"Skipped because step {step.name} could not start."
                    break
                if not success:
                    status = "failed"
                    skip_reason = f"Skipped because step {step.name} failed."
                    break
                for actor_name, actor in actors.items():
                    alive, details = actor_status(actor)
                    if not alive:
                        recorder.assertion(
                            f"actor_alive_after_{slugify(actor_name)}_{slugify(step.name)}",
                            "failed",
                            0,
                            details,
                        )
                        status = "failed"
                        skip_reason = f"Skipped because actor {actor_name} stopped after step {step.name}."
                        break
                if status != "passed":
                    break

            if skip_reason is not None and next_step_index < len(scenario.steps):
                record_skipped_steps(recorder, scenario.steps[next_step_index:], reason=skip_reason)

            print_progress("Collecting final snapshots")
            collect_namespace_snapshots(recorder, context, "final")
            for actor_name, actor in actors.items():
                alive, details = actor_status(actor)
                if not alive:
                    recorder.assertion(
                        f"actor_alive_before_cleanup_{slugify(actor_name)}",
                        "failed",
                        0,
                        details,
                    )
                    status = "failed"
        elif skip_reason is not None and next_step_index < len(scenario.steps):
            record_skipped_steps(recorder, scenario.steps[next_step_index:], reason=skip_reason)
    except ScenarioError as exc:
        recorder.event("orchestrator_error", "error", str(exc))
        recorder.note(f"orchestrator_error={exc}")
        if status == "passed":
            status = "error"
    finally:
        try:
            if setup_ok:
                copy_fixture_artifacts(recorder, fixture_payloads)

            for actor_name, actor in reversed(list(actors.items())):
                print_progress(f"Stopping actor {actor_name}")
                started_ms = now_ms()
                actor_stop_status, actor_stop_details = stop_actor(
                    actor,
                    timeout_s=actor_stop_timeout_s,
                )
                recorder.assertion(
                    f"stop_actor_{slugify(actor_name)}",
                    actor_stop_status,
                    now_ms() - started_ms,
                    actor_stop_details,
                )
                if actor_stop_status != "passed" and status == "passed":
                    status = "error"

            if setup_ok:
                for fixture_name, payload in reversed(list(fixture_payloads.items())):
                    started_ms = now_ms()
                    stop_status, stop_details = stop_fixture(recorder, payload)
                    recorder.assertion(
                        f"stop_fixture_{slugify(fixture_name)}",
                        stop_status,
                        now_ms() - started_ms,
                        stop_details,
                    )
                    if stop_status != "passed" and status == "passed":
                        status = "error"

                if keep_topology:
                    print_progress("Leaving topology running")
                    recorder.note("topology_left_running=1")
                    recorder.event("teardown_skipped", "info", "Topology left running by request")
                else:
                    print_progress("Tearing down topology")
                    teardown_ok = teardown_topology(recorder, topology)
                    if not teardown_ok and status == "passed":
                        status = "error"
        except ScenarioError as exc:
            recorder.event("teardown_error", "error", str(exc))
            recorder.note(f"teardown_error={exc}")
            if status == "passed":
                status = "error"
        finally:
            if not keep_topology:
                shutil.rmtree(lab_root, ignore_errors=True)

        recorder.metric("step_count", len(scenario.steps))
        recorder.event("run_finished", status, f"Scenario finished with status {status}")
        run_state.set_context(context)
        recorder.finalize(status)
        try:
            apply_tree_ownership(recorder.run_dir, artifact_owner)
        except OSError as exc:
            recorder.note(f"artifact_ownership_error={exc}")
            if status == "passed":
                status = "error"
                recorder.finalize(status)

    print_progress("Run complete")
    print(f"[SUMMARY] {recorder.run_dir / 'summary.txt'}")
    print((recorder.run_dir / "summary.txt").read_text(encoding="utf-8"), end="")
    return 0 if status == "passed" else 1
