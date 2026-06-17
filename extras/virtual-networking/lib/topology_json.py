#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.runner.models import ScenarioError
from lib.runner.topology_loader import emit_topology_action_lines, load_topology_file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read and normalize virtual-networking topologies")
    parser.add_argument(
        "action",
        choices=("defaults", "namespaces", "operations"),
    )
    parser.add_argument("topology_file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        topology = load_topology_file(Path(args.topology_file))
    except ScenarioError as exc:
        raise SystemExit(str(exc)) from exc
    for line in emit_topology_action_lines(topology, args.action):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
