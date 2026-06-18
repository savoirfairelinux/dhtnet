from __future__ import annotations

import argparse
import json
import shutil
import textwrap
from typing import Sequence

from .context_loader import (
    build_scenario_context,
    load_fixtures,
    role_context_key,
)
from .models import ScenarioError, ScenarioSpec
from .paths import DEFAULT_ARTIFACT_ROOT, FIXTURE_DIR


def format_wrapped_rows(
    *,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    wrap_index: int,
) -> str:
    string_rows = [tuple(str(value) for value in row) for row in rows]
    column_count = len(headers)
    separator = "  "
    widths = [0] * column_count
    for index, header in enumerate(headers):
        if index == wrap_index:
            continue
        widths[index] = max(
            len(header),
            *(len(row[index]) for row in string_rows),
        ) if string_rows else len(header)

    terminal_width = shutil.get_terminal_size(fallback=(100, 20)).columns
    fixed_width = sum(widths[index] for index in range(column_count) if index != wrap_index)
    wrap_width = max(
        24,
        len(headers[wrap_index]),
        terminal_width - fixed_width - len(separator) * (column_count - 1),
    )

    def format_line(values: Sequence[str]) -> str:
        parts: list[str] = []
        for index, value in enumerate(values):
            if index == wrap_index:
                parts.append(value)
            else:
                parts.append(f"{value:<{widths[index]}}")
        return separator.join(parts).rstrip()

    header_values = list(headers)
    divider_values = [
        "-" * (len(headers[index]) if index == wrap_index else widths[index])
        for index in range(column_count)
    ]
    lines = [format_line(header_values), format_line(divider_values)]
    for row in string_rows:
        wrapped = textwrap.wrap(row[wrap_index], width=wrap_width) or [""]
        for line_index, description_line in enumerate(wrapped):
            line_values = [
                row[index] if line_index == 0 else ""
                for index in range(column_count)
            ]
            line_values[wrap_index] = description_line
            lines.append(format_line(line_values))
    return "\n".join(lines)


def format_scenario_rows(scenarios: list[ScenarioSpec]) -> str:
    rows = [(scenario.name, scenario.topology, scenario.description) for scenario in scenarios]
    return format_wrapped_rows(
        headers=("SCENARIO", "TOPOLOGY", "DESCRIPTION"),
        rows=rows,
        wrap_index=2,
    )


def get_subparsers_action(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise ScenarioError("Parser is missing subcommands")


def print_help_for_topics(parser: argparse.ArgumentParser, topics: Sequence[str]) -> None:
    current_parser = parser
    for topic in topics:
        subparsers = get_subparsers_action(current_parser)
        next_parser = subparsers.choices.get(topic)
        if next_parser is None:
            parser.error(f"Unknown help topic: {' '.join(topics)}")
        current_parser = next_parser
    current_parser.print_help()


def print_progress(message: str) -> None:
    print(f"[RUN] {message}", flush=True)


def print_dry_run(scenario: ScenarioSpec) -> None:
    topology, context = build_scenario_context(
        scenario,
        artifact_root=DEFAULT_ARTIFACT_ROOT,
        run_id="<run-id>",
    )
    fixtures = load_fixtures(FIXTURE_DIR)
    print(f"Scenario: {scenario.name}")
    print(f"Description: {scenario.description}")
    print(f"Topology: {scenario.topology}")
    print(f"Lab: {scenario.lab}")
    print(f"Scenario file: {scenario.path}")
    print(f"Topology file: {topology.path}")
    if topology.roles:
        print("Roles:")
        for role in sorted(topology.roles.values(), key=lambda item: item.name):
            capabilities = f" [{', '.join(role.capabilities)}]" if role.capabilities else ""
            namespace = context[role_context_key(role.name, "namespace")]
            print(f"  - {role.name}: {namespace}{capabilities}")
    if scenario.fixtures:
        print("Fixtures:")
        for fixture_name in scenario.fixtures:
            fixture = fixtures.get(fixture_name)
            if fixture is None:
                print(f"  - {fixture_name}: <missing fixture definition>")
            else:
                print(f"  - {fixture_name}: {fixture.kind}")
    if scenario.actors:
        print("Actors:")
        for actor in scenario.actors:
            actor_role_ns = context[role_context_key(actor.role, "namespace")]
            extra = f", bootstrap_fixture={actor.bootstrap_fixture}" if actor.bootstrap_fixture else ""
            print(f"  - {actor.name}: {actor.kind} in role {actor.role} ({actor_role_ns}), wait={actor.wait_s:.1f}s{extra}")
    print("Steps:")
    for step in scenario.steps:
        parts = [f"probe={step.probe}"]
        if step.inputs:
            parts.append(f"inputs={json.dumps(step.inputs, sort_keys=True)}")
        print(f"  - {step.name}: " + ", ".join(parts))
