from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..result_summary import append_jsonl_record, build_summary_files
from .models import ScenarioError, TopologySpec
from .util import now_iso


@dataclass(frozen=True)
class ResultLayout:
    scenario: str
    run_id: str
    artifact_root: Path
    run_dir: Path
    meta_dir: Path
    captures_dir: Path
    events_file: Path
    assertions_file: Path
    captures_file: Path
    metrics_file: Path
    notes_file: Path
    fields_file: Path
    started_at: str

    @property
    def run_state_path(self) -> Path:
        return self.meta_dir / "run-state.json"

    def env_exports(self) -> dict[str, str]:
        return {
            "VNET_RESULT_SCENARIO": self.scenario,
            "VNET_RESULT_RUN_ID": self.run_id,
            "VNET_RESULT_DIR": str(self.run_dir),
            "VNET_RESULT_META_DIR": str(self.meta_dir),
            "VNET_RESULT_CAPTURES_DIR": str(self.captures_dir),
            "VNET_RESULT_EVENTS_FILE": str(self.events_file),
            "VNET_RESULT_ASSERTIONS_FILE": str(self.assertions_file),
            "VNET_RESULT_CAPTURES_FILE": str(self.captures_file),
            "VNET_RESULT_METRICS_FILE": str(self.metrics_file),
            "VNET_RESULT_NOTES_FILE": str(self.notes_file),
            "VNET_RESULT_FIELDS_FILE": str(self.fields_file),
            "VNET_RESULT_STARTED_AT": self.started_at,
        }


def build_result_layout(
    *,
    run_id: str,
    scenario: str,
    artifact_root: Path,
    run_dir: Path | None = None,
    meta_dir: Path | None = None,
    captures_dir: Path | None = None,
    started_at: str | None = None,
) -> ResultLayout:
    resolved_run_dir = run_dir or (artifact_root / run_id)
    resolved_meta_dir = meta_dir or (resolved_run_dir / ".meta")
    resolved_captures_dir = captures_dir or (resolved_run_dir / "captures")
    return ResultLayout(
        scenario=scenario,
        run_id=run_id,
        artifact_root=artifact_root,
        run_dir=resolved_run_dir,
        meta_dir=resolved_meta_dir,
        captures_dir=resolved_captures_dir,
        events_file=resolved_run_dir / "events.jsonl",
        assertions_file=resolved_meta_dir / "assertions.jsonl",
        captures_file=resolved_meta_dir / "captures.jsonl",
        metrics_file=resolved_meta_dir / "metrics.jsonl",
        notes_file=resolved_meta_dir / "notes.jsonl",
        fields_file=resolved_meta_dir / "fields.jsonl",
        started_at=started_at or now_iso(),
    )


def initialize_result_layout(
    *,
    run_id: str,
    scenario: str,
    artifact_root: Path,
    run_dir: Path | None = None,
    meta_dir: Path | None = None,
    captures_dir: Path | None = None,
    started_at: str | None = None,
) -> ResultLayout:
    layout = build_result_layout(
        run_id=run_id,
        scenario=scenario,
        artifact_root=artifact_root,
        run_dir=run_dir,
        meta_dir=meta_dir,
        captures_dir=captures_dir,
        started_at=started_at,
    )
    if layout.run_dir.exists():
        shutil.rmtree(layout.run_dir)
    layout.captures_dir.mkdir(parents=True, exist_ok=True)
    layout.meta_dir.mkdir(parents=True, exist_ok=True)
    for path in (
        layout.events_file,
        layout.assertions_file,
        layout.captures_file,
        layout.metrics_file,
        layout.notes_file,
        layout.fields_file,
    ):
        path.write_text("", encoding="utf-8")
    return layout


class ResultRecorder:
    def __init__(self, *, run_id: str, scenario: str, artifact_root: Path) -> None:
        layout = initialize_result_layout(
            run_id=run_id,
            scenario=scenario,
            artifact_root=artifact_root,
        )
        self.run_id = layout.run_id
        self.scenario = layout.scenario
        self.artifact_root = layout.artifact_root
        self.run_dir = layout.run_dir
        self.meta_dir = layout.meta_dir
        self.run_state_path = layout.run_state_path
        self.captures_dir = layout.captures_dir
        self.events_file = layout.events_file
        self.assertions_file = layout.assertions_file
        self.captures_file = layout.captures_file
        self.metrics_file = layout.metrics_file
        self.notes_file = layout.notes_file
        self.fields_file = layout.fields_file
        self.started_at = layout.started_at

    def event(self, event: str, status: str, message: str) -> None:
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
        append_jsonl_record(
            self.assertions_file,
            {
                "name": name,
                "status": status,
                "duration_ms": duration_ms,
                "details": details,
            },
        )

    def metric(self, key: str, value: Any) -> None:
        append_jsonl_record(self.metrics_file, {"key": key, "value": value})

    def note(self, note: str) -> None:
        append_jsonl_record(self.notes_file, {"note": note})

    def field(self, key: str, value: Any) -> None:
        append_jsonl_record(self.fields_file, {"key": key, "value": value})

    def record_capture(self, label: str, kind: str, relative_path: str) -> None:
        append_jsonl_record(
            self.captures_file,
            {"label": label, "kind": kind, "path": relative_path},
        )

    def copy_capture(self, *, source: Path, destination: str, label: str, kind: str) -> Path:
        if not source.exists():
            raise ScenarioError(f"Capture source does not exist: {source}")
        destination_path = self.captures_dir / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination_path)
        relative = destination_path.relative_to(self.captures_dir).as_posix()
        self.record_capture(label, kind, f"captures/{relative}")
        return destination_path

    def command_capture_path(self, filename: str) -> Path:
        path = self.captures_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def finalize(self, status: str) -> None:
        build_summary_files(
            output_dir=self.run_dir,
            scenario=self.scenario,
            status=status,
            started_at=self.started_at,
            ended_at=now_iso(),
            run_id=self.run_id,
            assertions=self.assertions_file,
            captures=self.captures_file,
            metrics=self.metrics_file,
            notes=self.notes_file,
            fields=self.fields_file,
        )


class RunState:
    def __init__(self, path: Path, *, run_id: str, scenario: str, lab: str) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "run_id": run_id,
            "scenario": scenario,
            "lab": lab,
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
            "file": str(topology.path),
            "defaults": dict(sorted(topology.defaults.items())),
            "namespaces": list(topology.namespaces),
            "roles": {
                role_name: {
                    "namespace_template": role.namespace,
                    "capabilities": list(role.capabilities),
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
