#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def iso_to_datetime(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def append_jsonl_record(path: Path, record: dict[str, Any]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return 0


def render_text(summary: dict[str, Any], *, captures_dir: Path | None = None) -> str:
    lines = [
        f"Scenario: {summary['scenario']}",
        f"Run ID: {summary['run_id']}",
        f"Status: {summary['status'].upper()}",
        f"Started: {summary['started_at']}",
        f"Ended: {summary['ended_at']}",
        f"Duration: {summary['duration_s']:.3f}s",
    ]

    for optional_key in ("topology",):
        if optional_key in summary:
            label = optional_key.replace("_", " ").title()
            lines.append(f"{label}: {summary[optional_key]}")

    lines.append("")
    lines.append("Assertions:")
    if summary["assertions"]:
        for assertion in summary["assertions"]:
            duration = assertion.get("duration_ms")
            duration_label = f"{duration}ms" if duration is not None else "n/a"
            lines.append(
                f"  - [{assertion['status'].upper()}] {assertion['name']} ({duration_label})"
            )

            if assertion['status'] == "failed":
                details = assertion.get("details")
                if details:
                    lines.append(f"      {details}")
    else:
        lines.append("  - (none)")

    lines.append("")
    lines.append("Metrics:")
    if summary["metrics"]:
        for key, value in summary["metrics"].items():
            lines.append(f"  - {key}: {value}")
    else:
        lines.append("  - (none)")

    lines.append("")
    lines.append("Captures:")
    lines.append(f"  - Count: {len(summary['captures'])}")
    if captures_dir is not None:
        lines.append(f"  - Directory: {captures_dir.resolve()}")

    lines.append("")
    lines.append("Notes:")
    if summary["notes"]:
        for note in summary["notes"]:
            lines.append(f"  - {note}")
    else:
        lines.append("  - (none)")

    return "\n".join(lines) + "\n"


def build_summary(
    *,
    run_id: str,
    scenario: str,
    status: str,
    started_at: str,
    ended_at: str,
    assertions: list[dict[str, Any]],
    captures: list[dict[str, Any]],
    metrics: dict[str, Any],
    notes: list[str],
    fields: dict[str, Any],
) -> dict[str, Any]:
    started_at_dt = iso_to_datetime(started_at)
    ended_at_dt = iso_to_datetime(ended_at)
    duration_s = (ended_at_dt - started_at_dt).total_seconds()

    summary: dict[str, Any] = {
        "run_id": run_id,
        "scenario": scenario,
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_s": duration_s,
        "assertions": assertions,
        "metrics": metrics,
        "captures": captures,
        "notes": notes,
    }
    summary.update(fields)
    return summary


def write_summary_files(
    *,
    output_dir: Path,
    summary: dict[str, Any],
    captures_dir: Path | None = None,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_json = output_dir / "summary.json"
    summary_txt = output_dir / "summary.txt"
    resolved_captures_dir = captures_dir or (output_dir / "captures")

    with summary_json.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=False)
        handle.write("\n")

    with summary_txt.open("w", encoding="utf-8") as handle:
        handle.write(render_text(summary, captures_dir=resolved_captures_dir))

    return 0
