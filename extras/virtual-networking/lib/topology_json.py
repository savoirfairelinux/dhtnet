#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def fail(topology_path: Path, message: str) -> None:
    raise SystemExit(f"{topology_path}: {message}")


def require_string(topology_path: Path, value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        fail(topology_path, f"expected non-empty string for {field_name}")
    if any(char in value for char in ("\n", "\r", "\t")):
        fail(topology_path, f"{field_name} must not contain tabs or newlines")
    return value


def require_string_list(topology_path: Path, value: Any, *, field_name: str) -> list[str]:
    if not isinstance(value, list):
        fail(topology_path, f"expected {field_name} to be a list")
    return [
        require_string(topology_path, item, field_name=f"{field_name}[]")
        for item in value
    ]


def require_operation_keys(
    topology_path: Path,
    raw: dict[str, Any],
    *,
    allowed: set[str],
    field_name: str,
) -> None:
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        fail(topology_path, f"{field_name} has unexpected keys: {', '.join(unexpected)}")


def optional_string(
    topology_path: Path,
    raw: dict[str, Any],
    key: str,
    *,
    field_name: str,
) -> str:
    value = raw.get(key)
    if value is None:
        return ""
    return require_string(topology_path, value, field_name=f"{field_name}.{key}")


def require_defaults(topology_path: Path, value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(topology_path, "expected defaults to be an object")

    normalized: dict[str, str] = {}
    for key, raw_value in value.items():
        key = require_string(topology_path, key, field_name="defaults key")
        if not key.replace("_", "a").isalnum() or key[0].isdigit():
            fail(topology_path, f"invalid defaults key {key!r}")
        normalized[key] = require_string(
            topology_path,
            raw_value,
            field_name=f"defaults.{key}",
        )
    return normalized


def require_roles(topology_path: Path, value: Any) -> list[tuple[str, str, list[str]]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        fail(topology_path, "expected roles to be an object")

    normalized: list[tuple[str, str, list[str]]] = []
    for role_name, raw_role in value.items():
        role_name = require_string(topology_path, role_name, field_name="roles key")
        if not isinstance(raw_role, dict):
            fail(topology_path, f"expected roles.{role_name} to be an object")
        require_operation_keys(
            topology_path,
            raw_role,
            allowed={"namespace", "capabilities"},
            field_name=f"roles.{role_name}",
        )
        capabilities = raw_role.get("capabilities", [])
        if not isinstance(capabilities, list):
            fail(topology_path, f"expected roles.{role_name}.capabilities to be a list")
        normalized.append(
            (
                role_name,
                require_string(
                    topology_path,
                    raw_role.get("namespace"),
                    field_name=f"roles.{role_name}.namespace",
                ),
                [
                    require_string(
                        topology_path,
                        item,
                        field_name=f"roles.{role_name}.capabilities[]",
                    )
                    for item in capabilities
                ],
            )
        )
    return normalized


def normalize_operation(topology_path: Path, index: int, raw: Any) -> list[str]:
    field_name = f"operations[{index}]"
    if not isinstance(raw, dict):
        fail(topology_path, f"expected {field_name} to be an object")

    op_type = require_string(
        topology_path,
        raw.get("type"),
        field_name=f"{field_name}.type",
    )
    if op_type in {"create-namespaces", "set-loopbacks-up"}:
        require_operation_keys(
            topology_path,
            raw,
            allowed={"type", "namespaces"},
            field_name=field_name,
        )
        return [
            op_type,
            *require_string_list(
                topology_path,
                raw.get("namespaces"),
                field_name=f"{field_name}.namespaces",
            ),
        ]
    if op_type == "connect-veth":
        require_operation_keys(
            topology_path,
            raw,
            allowed={"type", "ns_a", "iface_a", "ns_b", "iface_b"},
            field_name=field_name,
        )
        return [
            op_type,
            require_string(topology_path, raw.get("ns_a"), field_name=f"{field_name}.ns_a"),
            require_string(topology_path, raw.get("iface_a"), field_name=f"{field_name}.iface_a"),
            require_string(topology_path, raw.get("ns_b"), field_name=f"{field_name}.ns_b"),
            require_string(topology_path, raw.get("iface_b"), field_name=f"{field_name}.iface_b"),
        ]
    if op_type == "configure-ipv4-interface":
        require_operation_keys(
            topology_path,
            raw,
            allowed={"type", "ns", "iface", "cidr"},
            field_name=field_name,
        )
        return [
            op_type,
            require_string(topology_path, raw.get("ns"), field_name=f"{field_name}.ns"),
            require_string(topology_path, raw.get("iface"), field_name=f"{field_name}.iface"),
            require_string(topology_path, raw.get("cidr"), field_name=f"{field_name}.cidr"),
        ]
    if op_type == "add-default-route":
        require_operation_keys(
            topology_path,
            raw,
            allowed={"type", "ns", "via", "dev", "metric"},
            field_name=field_name,
        )
        return [
            op_type,
            require_string(topology_path, raw.get("ns"), field_name=f"{field_name}.ns"),
            require_string(topology_path, raw.get("via"), field_name=f"{field_name}.via"),
            optional_string(topology_path, raw, "dev", field_name=field_name),
            optional_string(topology_path, raw, "metric", field_name=field_name),
        ]
    if op_type == "add-device-route":
        require_operation_keys(
            topology_path,
            raw,
            allowed={"type", "ns", "destination", "dev", "metric"},
            field_name=field_name,
        )
        return [
            op_type,
            require_string(topology_path, raw.get("ns"), field_name=f"{field_name}.ns"),
            require_string(
                topology_path,
                raw.get("destination"),
                field_name=f"{field_name}.destination",
            ),
            require_string(topology_path, raw.get("dev"), field_name=f"{field_name}.dev"),
            optional_string(topology_path, raw, "metric", field_name=field_name),
        ]
    if op_type == "setup-basic-nat-router":
        require_operation_keys(
            topology_path,
            raw,
            allowed={"type", "ns", "lan_iface", "wan_iface"},
            field_name=field_name,
        )
        return [
            op_type,
            require_string(topology_path, raw.get("ns"), field_name=f"{field_name}.ns"),
            require_string(
                topology_path,
                raw.get("lan_iface"),
                field_name=f"{field_name}.lan_iface",
            ),
            require_string(
                topology_path,
                raw.get("wan_iface"),
                field_name=f"{field_name}.wan_iface",
            ),
        ]

    fail(topology_path, f"unsupported operation type {op_type!r}")


def load_topology_document(topology_path: Path) -> dict[str, Any]:
    try:
        data = json.loads(topology_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(topology_path, "file not found")
    except json.JSONDecodeError as exc:
        fail(topology_path, f"invalid JSON: {exc}")

    if not isinstance(data, dict):
        fail(topology_path, "topology file must contain a JSON object")

    operations = data.get("operations")
    if not isinstance(operations, list):
        fail(topology_path, "expected operations to be a list")

    return {
        "name": require_string(topology_path, data.get("name"), field_name="name"),
        "description": require_string(
            topology_path,
            data.get("description"),
            field_name="description",
        ),
        "defaults": require_defaults(topology_path, data.get("defaults")),
        "roles": require_roles(topology_path, data.get("roles")),
        "namespaces": require_string_list(
            topology_path,
            data.get("namespaces"),
            field_name="namespaces",
        ),
        "state_vars": require_string_list(
            topology_path,
            data.get("state_vars"),
            field_name="state_vars",
        ),
        "operations": [
            normalize_operation(topology_path, index, raw_operation)
            for index, raw_operation in enumerate(operations)
        ],
    }


def emit_action_lines(topology: dict[str, Any], action: str) -> list[str]:
    if action == "defaults":
        return [f"{key}\t{value}" for key, value in topology["defaults"].items()]
    if action == "roles":
        return [
            f"{name}\t{namespace}\t{','.join(capabilities)}"
            for name, namespace, capabilities in topology["roles"]
        ]
    if action == "namespaces":
        return list(topology["namespaces"])
    if action == "state-vars":
        return list(topology["state_vars"])
    if action == "operations":
        return ["\t".join(operation) for operation in topology["operations"]]
    raise SystemExit(f"unsupported action {action!r}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read and normalize virtual-networking topologies")
    parser.add_argument(
        "action",
        choices=("defaults", "roles", "namespaces", "state-vars", "operations"),
    )
    parser.add_argument("topology_file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    topology = load_topology_document(Path(args.topology_file))
    for line in emit_action_lines(topology, args.action):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
