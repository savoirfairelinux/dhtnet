from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any


class ScenarioError(RuntimeError):
    pass


@dataclass(frozen=True)
class CopyOutputSpec:
    source: str
    destination: str
    label: str
    kind: str = "captured-file"


@dataclass(frozen=True)
class StepSpec:
    name: str
    step_type: str = "probe"
    inputs: dict[str, Any] = field(default_factory=dict)
    capture: str | None = None
    label: str | None = None
    kind: str | None = None
    allow_failure: bool = False
    copy_outputs: list[CopyOutputSpec] = field(default_factory=list)
    probe: str | None = None
    assertions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ActorSpec:
    name: str
    kind: str
    role: str
    wait_s: float = 0.0
    bootstrap_fixture: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    description: str
    topology: str
    lab: str
    steps: list[StepSpec]
    notes: list[str]
    fields: dict[str, Any]
    path: Path
    fixtures: list[str] = field(default_factory=list)
    actors: list[ActorSpec] = field(default_factory=list)


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    description: str
    kind: str
    requires_roles: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    options: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None


@dataclass(frozen=True)
class ProbeSpec:
    name: str
    description: str
    backend: str
    path: Path
    required_inputs: tuple[str, ...] = ()
    argv: list[str] = field(default_factory=list)
    argv_prefix: list[str] = field(default_factory=list)
    namespace_input: str | None = None
    argv_input: str | None = None
    flag_order: tuple[str, ...] = ()
    default_capture: str | None = None
    default_label: str | None = None
    default_kind: str = "command-output"
    default_copy_outputs: list[CopyOutputSpec] = field(default_factory=list)
    outputs_file: str | None = None


@dataclass(frozen=True)
class TopologyRoleSpec:
    name: str
    namespace: str
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class TopologySpec:
    name: str
    path: Path
    defaults: dict[str, str]
    roles: dict[str, TopologyRoleSpec]
    namespaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class LaunchUser:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    env: dict[str, str]


@dataclass
class ManagedActor:
    name: str
    kind: str
    namespace: str
    launch_command: str
    user: LaunchUser
    process: subprocess.Popen[str]
    log_handle: IO[str]
    log_path: Path
    meta_path: Path
    log_capture_path: str
    meta_capture_path: str
    ready_path: Path | None = None
    output_path: Path | None = None
    output_capture_path: str | None = None
    outputs: dict[str, Any] = field(default_factory=dict)
