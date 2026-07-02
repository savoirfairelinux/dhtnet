from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any


class ScenarioError(RuntimeError):
    pass


@dataclass(frozen=True)
class StepSpec:
    name: str
    inputs: dict[str, Any] = field(default_factory=dict)
    allow_failure: bool = False
    probe: str | None = None


@dataclass(frozen=True)
class ServiceReadinessSpec:
    type: str = "none"
    timeout_s: float = 0.0


@dataclass(frozen=True)
class ServiceOutputsSpec:
    type: str = "none"
    required: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    kind: str
    role: str
    argv: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    readiness: ServiceReadinessSpec = field(default_factory=ServiceReadinessSpec)
    outputs: ServiceOutputsSpec = field(default_factory=ServiceOutputsSpec)


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    description: str
    topology: str
    steps: list[StepSpec]
    notes: list[str]
    path: Path
    fixtures: list[str] = field(default_factory=list)
    services: list[ServiceSpec] = field(default_factory=list)


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    description: str
    kind: str
    options: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None


@dataclass(frozen=True)
class ProbeSpec:
    name: str
    description: str
    path: Path
    required_inputs: tuple[str, ...] = ()
    probe_sequence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class TopologyRoleSpec:
    name: str
    namespace: str


@dataclass(frozen=True)
class TopologySpec:
    name: str
    description: str
    path: Path
    defaults: dict[str, str]
    roles: dict[str, TopologyRoleSpec]
    namespaces: tuple[str, ...] = ()
    operations: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class LaunchUser:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    env: dict[str, str]


@dataclass
class ManagedService:
    name: str
    kind: str
    namespace: str
    argv: list[str]
    user: LaunchUser
    process: subprocess.Popen[str]
    log_handle: IO[str]
    log_path: Path
    log_capture_path: str
    ready_path: Path | None = None
    output_path: Path | None = None
    required_outputs: tuple[str, ...] = ()
    outputs: dict[str, Any] = field(default_factory=dict)
