#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from lib.reporting.cli_printer import (
    format_scenario_rows,
    print_dry_run,
    print_help_for_topics,
)
from lib.loaders.context_loader import (
    load_fixtures,
    load_probes,
    load_scenarios,
    validate_scenario_against_fixtures,
)
from lib.loaders.topology_loader import load_topology
from lib.core.models import ScenarioError, ScenarioSpec
from lib.core.paths import DEFAULT_ARTIFACT_ROOT, FIXTURE_DIR, PROBE_DIR, SCENARIO_DIR
from lib.runtime.runtime_orchestrator import run_scenario
from lib.core.util import default_run_id, slugify, validate_run_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run virtual-networking scenarios")
    parser.add_argument(
        "--scenario-dir",
        default=str(SCENARIO_DIR),
        help="Directory containing scenario JSON files",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    help_parser = subparsers.add_parser("help", help="Show help for the CLI or a subcommand")
    help_parser.add_argument("topics", nargs="*")

    subparsers.add_parser("list", help="List available scenarios")

    describe = subparsers.add_parser("describe", help="Describe a scenario")
    describe.add_argument("scenario")

    run = subparsers.add_parser(
        "run",
        help="Run a scenario, or 'all' to run every scenario",
    )
    run.add_argument("scenario", help="Scenario name, or 'all'")
    run.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    run.add_argument("--run-id")
    run.add_argument("--keep-topology", action="store_true")
    run.add_argument("--actor-stop-timeout-s", type=float, default=10.0)
    run.add_argument("--dry-run", action="store_true")

    return parser


def run_all_scenarios(
    scenarios: list[ScenarioSpec],
    *,
    artifact_root: Path,
    run_id_prefix: str | None,
    keep_topology: bool,
    actor_stop_timeout_s: float,
) -> int:
    failed: list[str] = []
    total = len(scenarios)
    for index, scenario in enumerate(scenarios, start=1):
        print(f"[RUN] Running scenario {index}/{total}: {scenario.name}\n", flush=True)
        run_id = (
            f"{run_id_prefix}_{slugify(scenario.name)}"
            if run_id_prefix is not None
            else default_run_id(scenario.name)
        )
        try:
            validate_run_id(run_id)
        except ScenarioError as exc:
            raise ScenarioError(
                f"Generated run ID for scenario {scenario.name!r} is invalid: {exc}"
            ) from exc
        scenario_exit_code = run_scenario(
            scenario,
            artifact_root=artifact_root,
            run_id=run_id,
            keep_topology=keep_topology,
            actor_stop_timeout_s=actor_stop_timeout_s,
        )
        print('\n\n')
        if scenario_exit_code != 0:
            failed.append(scenario.name)
    passed_count = total - len(failed)
    if failed:
        print(
            f"[RUN] All scenarios complete: {passed_count} passed, {len(failed)} failed",
            flush=True,
        )
        print(f"[RUN] Failed scenarios: {', '.join(failed)}", flush=True)
        return 1
    print(f"[RUN] All scenarios complete: {passed_count} passed, 0 failed", flush=True)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "help":
        print_help_for_topics(parser, args.topics)
        return 0

    scenarios = load_scenarios(Path(args.scenario_dir))
    fixtures = load_fixtures(FIXTURE_DIR)
    probes = load_probes(PROBE_DIR)
    for scenario in scenarios.values():
        validate_scenario_against_fixtures(scenario, load_topology(scenario.topology), fixtures, probes)

    if args.command == "list":
        print(format_scenario_rows(list(scenarios.values())))
        return 0

    if args.command == "describe":
        scenario = scenarios.get(args.scenario)
        if scenario is None:
            parser.error(f"Unknown scenario: {args.scenario}")
        print_dry_run(scenario)
        return 0

    if args.command == "run":
        ordered_scenarios = list(scenarios.values())
        if args.scenario == "all":
            if args.dry_run:
                for scenario in ordered_scenarios:
                    print_dry_run(scenario)
                    print()
                return 0
            if args.run_id is not None:
                try:
                    validate_run_id(args.run_id)
                except ScenarioError as exc:
                    parser.error(str(exc))
            try:
                return run_all_scenarios(
                    ordered_scenarios,
                    artifact_root=Path(args.artifact_root),
                    run_id_prefix=args.run_id,
                    keep_topology=args.keep_topology,
                    actor_stop_timeout_s=args.actor_stop_timeout_s,
                )
            except ScenarioError as exc:
                parser.error(str(exc))

        scenario = scenarios.get(args.scenario)
        if scenario is None:
            parser.error(f"Unknown scenario: {args.scenario}")
        if args.dry_run:
            print_dry_run(scenario)
            return 0
        run_id = args.run_id or default_run_id(scenario.name)
        try:
            validate_run_id(run_id)
        except ScenarioError as exc:
            parser.error(str(exc))
        return run_scenario(
            scenario,
            artifact_root=Path(args.artifact_root),
            run_id=run_id,
            keep_topology=args.keep_topology,
            actor_stop_timeout_s=args.actor_stop_timeout_s,
        )

    parser.error(f"Unsupported command: {args.command}")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
