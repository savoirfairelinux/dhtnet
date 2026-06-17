#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
from pathlib import Path

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.runner.models import ScenarioError
from lib.runner.result_recorder import ResultRecorder, initialize_result_layout
from lib.runner.util import default_run_id


def render_shell_exports(env_exports: dict[str, str]) -> str:
    return "\n".join(
        f"export {key}={shlex.quote(value)}"
        for key, value in env_exports.items()
    ) + "\n"


def open_recorder() -> ResultRecorder:
    return ResultRecorder.from_env(os.environ)


def init_shell_environment(args: argparse.Namespace) -> int:
    layout = initialize_result_layout(
        run_id=args.run_id,
        scenario=args.scenario,
        artifact_root=Path(args.artifact_root),
        run_dir=Path(args.result_dir) if args.result_dir else None,
        meta_dir=Path(args.meta_dir) if args.meta_dir else None,
        captures_dir=Path(args.captures_dir) if args.captures_dir else None,
        started_at=args.started_at,
    )
    print(render_shell_exports(layout.env_exports()), end="")
    return 0


def default_run_id_command(args: argparse.Namespace) -> int:
    print(default_run_id(args.scenario))
    return 0


def record_event(args: argparse.Namespace) -> int:
    open_recorder().event(args.event, args.status, args.message)
    return 0


def record_field(args: argparse.Namespace) -> int:
    open_recorder().field(args.key, args.value)
    return 0


def record_assertion(args: argparse.Namespace) -> int:
    open_recorder().assertion(args.name, args.status, args.duration_ms, args.details)
    return 0


def record_metric(args: argparse.Namespace) -> int:
    open_recorder().metric(args.key, args.value)
    return 0


def record_note(args: argparse.Namespace) -> int:
    open_recorder().note(args.note)
    return 0


def record_capture(args: argparse.Namespace) -> int:
    open_recorder().record_capture(args.label, args.kind, args.path)
    return 0


def finalize_run(args: argparse.Namespace) -> int:
    open_recorder().finalize(args.status)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write virtual-networking results via the shared recorder")
    subparsers = parser.add_subparsers(dest="command", required=True)

    default_run_id_parser = subparsers.add_parser("default-run-id", help="Build a default run ID")
    default_run_id_parser.add_argument("scenario")

    init_shell_parser = subparsers.add_parser("init-shell", help="Initialize a result bundle and print shell exports")
    init_shell_parser.add_argument("--artifact-root", required=True)
    init_shell_parser.add_argument("--scenario", required=True)
    init_shell_parser.add_argument("--run-id", required=True)
    init_shell_parser.add_argument("--result-dir")
    init_shell_parser.add_argument("--meta-dir")
    init_shell_parser.add_argument("--captures-dir")
    init_shell_parser.add_argument("--started-at")

    event_parser = subparsers.add_parser("event", help="Append an event record")
    event_parser.add_argument("--event", required=True)
    event_parser.add_argument("--status", required=True)
    event_parser.add_argument("--message", required=True)

    field_parser = subparsers.add_parser("field", help="Append a field record")
    field_parser.add_argument("--key", required=True)
    field_parser.add_argument("--value", required=True)

    assertion_parser = subparsers.add_parser("assertion", help="Append an assertion record")
    assertion_parser.add_argument("--name", required=True)
    assertion_parser.add_argument("--status", required=True)
    assertion_parser.add_argument("--duration-ms", type=int, required=True)
    assertion_parser.add_argument("--details", default="")

    metric_parser = subparsers.add_parser("metric", help="Append a metric record")
    metric_parser.add_argument("--key", required=True)
    metric_parser.add_argument("--value", required=True)

    note_parser = subparsers.add_parser("note", help="Append a note record")
    note_parser.add_argument("--note", required=True)

    capture_parser = subparsers.add_parser("capture", help="Append a capture record")
    capture_parser.add_argument("--label", required=True)
    capture_parser.add_argument("--kind", required=True)
    capture_parser.add_argument("--path", required=True)

    finalize_parser = subparsers.add_parser("finalize", help="Render summary.json and summary.txt")
    finalize_parser.add_argument("--status", required=True)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "default-run-id":
            return default_run_id_command(args)
        if args.command == "init-shell":
            return init_shell_environment(args)
        if args.command == "event":
            return record_event(args)
        if args.command == "field":
            return record_field(args)
        if args.command == "assertion":
            return record_assertion(args)
        if args.command == "metric":
            return record_metric(args)
        if args.command == "note":
            return record_note(args)
        if args.command == "capture":
            return record_capture(args)
        if args.command == "finalize":
            return finalize_run(args)
    except ScenarioError as exc:
        raise SystemExit(str(exc)) from exc
    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
