from __future__ import annotations

import shlex
import subprocess

from .lifecycle import execute_lifecycle_command, execute_nonfatal_cleanup, shell_function_command
from lib.core.models import TopologySpec
from lib.reporting.result_recorder import ResultRecorder


def topology_command_env(topology: TopologySpec, context: dict[str, str]) -> dict[str, str]:
    return {key: context[key] for key in topology.defaults if key in context}


def setup_topology(recorder: ResultRecorder, topology: TopologySpec, context: dict[str, str]) -> bool:
    return execute_lifecycle_command(
        recorder,
        assertion_name="setup_topology",
        event_name="setup_started",
        argv=shell_function_command("vnet_fixture_apply_topology", str(topology.path)),
        capture_name="setup.txt",
        env=topology_command_env(topology, context),
    )


def preclean_topology(recorder: ResultRecorder, topology: TopologySpec, context: dict[str, str]) -> None:
    execute_nonfatal_cleanup(
        recorder,
        argv=shell_function_command("vnet_fixture_delete_topology_namespaces", str(topology.path)),
        capture_name="pre-cleanup.txt",
        env=topology_command_env(topology, context),
    )


def teardown_topology(recorder: ResultRecorder, topology: TopologySpec, context: dict[str, str]) -> bool:
    return execute_lifecycle_command(
        recorder,
        assertion_name="teardown_topology",
        event_name="teardown_started",
        argv=shell_function_command("vnet_fixture_delete_topology_namespaces", str(topology.path)),
        capture_name="teardown.txt",
        env=topology_command_env(topology, context),
    )


def snapshot_command(handle, argv: list[str]) -> int:
    handle.write(f"$ {shlex.join(argv)}\n\n")
    try:
        completed = subprocess.run(argv, stdout=handle, stderr=subprocess.STDOUT, text=True, check=False)
    except OSError as exc:
        handle.write(f"ERROR: {exc}\n")
        return 127
    handle.write("\n")
    return completed.returncode


def collect_namespace_snapshots(recorder: ResultRecorder, context: dict[str, str], phase: str) -> None:
    namespaces: dict[str, str] = {}
    for key, value in context.items():
        if key.endswith("_NS") and value:
            namespaces.setdefault(value, key)

    recorder.metric("namespace_count", len(namespaces))
    capture_path = recorder.command_capture_path(f"{phase}-namespace-snapshot.txt")
    failures: list[str] = []
    with capture_path.open("w", encoding="utf-8") as handle:
        rc = snapshot_command(handle, ["ip", "netns", "list"])
        if rc != 0:
            failures.append(f"ip netns list exited {rc}")
        for namespace in sorted(namespaces):
            handle.write(f"## {namespace} ({namespaces[namespace]})\n\n")
            for label, argv in (
                ("addr", ["ip", "-n", namespace, "addr", "show"]),
                ("route", ["ip", "-n", namespace, "route", "show"]),
            ):
                rc = snapshot_command(handle, argv)
                if rc != 0:
                    failures.append(f"{namespace} {label} exited {rc}")

    capture = recorder.record_command_capture(f"{phase} namespace snapshot", "state-dump", capture_path)
    if failures:
        recorder.note(f"{phase}_namespace_snapshot_failures={'; '.join(failures)}")
    elif not capture:
        recorder.note(f"{phase}_namespace_snapshot_empty=1")
