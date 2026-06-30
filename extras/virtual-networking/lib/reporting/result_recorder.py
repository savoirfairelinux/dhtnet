from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .result_summary import append_jsonl_record, build_summary, write_summary_files
from lib.core.models import ScenarioError, TopologySpec
from lib.core.util import now_iso, validate_run_id


@dataclass(frozen=True)
class ResultLayout:
    scenario: str
    run_id: str
    artifact_root: Path
    run_dir: Path
    captures_dir: Path
    events_file: Path | None
    started_at: str

    @property
    def run_state_path(self) -> Path:
        return self.run_dir / "run-state.json"


def build_result_layout(
    *,
    run_id: str,
    scenario: str,
    artifact_root: Path,
    run_dir: Path | None = None,
    captures_dir: Path | None = None,
    started_at: str | None = None,
    write_events: bool = True,
) -> ResultLayout:
    run_id = validate_run_id(run_id)
    resolved_artifact_root = artifact_root.resolve(strict=False)
    resolved_run_dir = (
        run_dir.resolve(strict=False)
        if run_dir is not None
        else (resolved_artifact_root / run_id).resolve(strict=False)
    )
    if resolved_run_dir == resolved_artifact_root:
        raise ScenarioError("run directory must not be the artifact root")
    try:
        resolved_run_dir.relative_to(resolved_artifact_root)
    except ValueError as exc:
        raise ScenarioError(
            f"run directory {resolved_run_dir} must stay under artifact root {resolved_artifact_root}"
        ) from exc

    resolved_captures_dir = (
        captures_dir.resolve(strict=False) if captures_dir is not None else (resolved_run_dir / "captures")
    )
    return ResultLayout(
        scenario=scenario,
        run_id=run_id,
        artifact_root=resolved_artifact_root,
        run_dir=resolved_run_dir,
        captures_dir=resolved_captures_dir,
        events_file=resolved_run_dir / "events.jsonl" if write_events else None,
        started_at=started_at or now_iso(),
    )


def initialize_result_layout(
    *,
    run_id: str,
    scenario: str,
    artifact_root: Path,
    run_dir: Path | None = None,
    captures_dir: Path | None = None,
    started_at: str | None = None,
    write_events: bool = True,
) -> ResultLayout:
    layout = build_result_layout(
        run_id=run_id,
        scenario=scenario,
        artifact_root=artifact_root,
        run_dir=run_dir,
        captures_dir=captures_dir,
        started_at=started_at,
        write_events=write_events,
    )
    if layout.run_dir.exists():
        shutil.rmtree(layout.run_dir)
    layout.captures_dir.mkdir(parents=True, exist_ok=True)
    if layout.events_file is not None:
        layout.events_file.write_text("", encoding="utf-8")
    return layout


class ResultRecorder:
    def __init__(self, *, run_id: str, scenario: str, artifact_root: Path) -> None:
        self._apply_layout(
            initialize_result_layout(
                run_id=run_id,
                scenario=scenario,
                artifact_root=artifact_root,
            )
        )

    @classmethod
    def from_layout(cls, layout: ResultLayout) -> ResultRecorder:
        recorder = cls.__new__(cls)
        recorder._apply_layout(layout)
        return recorder

    def _apply_layout(self, layout: ResultLayout) -> None:
        self.run_id = layout.run_id
        self.scenario = layout.scenario
        self.artifact_root = layout.artifact_root
        self.run_dir = layout.run_dir
        self.run_state_path = layout.run_state_path
        self.captures_dir = layout.captures_dir
        self.events_file = layout.events_file
        self.started_at = layout.started_at
        self.assertions: list[dict[str, Any]] = []
        self.captures: list[dict[str, Any]] = []
        self.metrics: dict[str, Any] = {}
        self.notes: list[str] = []
        self.fields: dict[str, Any] = {}

    def event(self, event: str, status: str, message: str) -> None:
        if self.events_file is None:
            return
        append_jsonl_record(
            self.events_file,
            {
                "timestamp": now_iso(),
                "event": event,
                "status": status,
                "message": message,
            },
        )

    def assertion(self, name: str, status: str, duration_ms: int, details: str) -> None:
        self.assertions.append(
            {
                "name": name,
                "status": status,
                "duration_ms": duration_ms,
                "details": details,
            }
        )

    def metric(self, key: str, value: Any) -> None:
        self.metrics[key] = value

    def note(self, note: str) -> None:
        self.notes.append(note)

    def field(self, key: str, value: Any) -> None:
        self.fields[key] = value

    def record_capture(self, label: str, kind: str, relative_path: str) -> None:
        self.captures.append({"label": label, "kind": kind, "path": relative_path})

    def copy_capture(self, *, source: Path, destination: str, label: str, kind: str) -> Path:
        if not source.exists():
            raise ScenarioError(f"Capture source does not exist: {source}")
        destination_path = self.captures_dir / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination_path)
        self.record_capture(label, kind, self.capture_reference(destination_path))
        return destination_path

    def command_capture_path(self, filename: str) -> Path:
        path = self.captures_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def capture_reference(self, path: Path) -> str:
        relative = path.relative_to(self.captures_dir).as_posix()
        if self.captures_dir == self.run_dir:
            return relative
        return f"captures/{relative}"

    def command_capture_has_output(self, path: Path) -> bool:
        if not path.exists():
            return False
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            return False
        if lines[0].startswith("$ "):
            body_start = 2 if len(lines) > 1 and not lines[1].strip() else 1
            return bool("\n".join(lines[body_start:]).strip())
        return bool("\n".join(lines).strip())

    def record_command_capture(self, label: str, kind: str, path: Path) -> str:
        if not self.command_capture_has_output(path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            return ""
        reference = self.capture_reference(path)
        self.record_capture(label, kind, reference)
        return reference

    def finalize(self, status: str) -> None:
        summary = build_summary(
            status=status,
            started_at=self.started_at,
            ended_at=now_iso(),
            run_id=self.run_id,
            scenario=self.scenario,
            assertions=self.assertions,
            captures=self.captures,
            metrics=self.metrics,
            notes=self.notes,
            fields=self.fields,
        )
        write_summary_files(
            output_dir=self.run_dir,
            summary=summary,
            captures_dir=self.captures_dir,
        )


class RunState:
    def __init__(self, path: Path, *, run_id: str, scenario: str) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "run_id": run_id,
            "scenario": scenario,
            "topology": {},
            "context": {},
            "fixtures": {},
            "actors": {},
            "probes": {},
        }
        self.flush()

    def flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    def set_topology(self, topology: TopologySpec) -> None:
        self.data["topology"] = {
            "name": topology.name,
            "description": topology.description,
            "file": str(topology.path),
            "defaults": dict(sorted(topology.defaults.items())),
            "namespaces": list(topology.namespaces),
            "operations": [list(operation) for operation in topology.operations],
            "roles": {
                role_name: {
                    "namespace_template": role.namespace,
                }
                for role_name, role in sorted(topology.roles.items())
            },
        }
        self.flush()

    def set_context(self, context: dict[str, str]) -> None:
        self.data["context"] = dict(sorted(context.items()))
        self.flush()

    def set_fixture(self, fixture_name: str, payload: dict[str, Any]) -> None:
        self.data.setdefault("fixtures", {})[fixture_name] = payload
        self.flush()

    def set_actor(self, actor_name: str, payload: dict[str, Any]) -> None:
        self.data.setdefault("actors", {})[actor_name] = payload
        self.flush()

    def set_probe(self, step_name: str, payload: dict[str, Any]) -> None:
        self.data.setdefault("probes", {})[step_name] = payload
        self.flush()
