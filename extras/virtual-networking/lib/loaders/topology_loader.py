from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.core.models import ScenarioError, TopologyRoleSpec, TopologySpec
from lib.core.paths import TOPOLOGY_DIR


def require_string(value: Any, *, field_name: str, topology_path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{topology_path}: expected non-empty string for {field_name}")
    if any(char in value for char in ("\n", "\r", "\t")):
        raise ScenarioError(f"{topology_path}: {field_name} must not contain tabs or newlines")
    return value


def require_string_list(value: Any, *, field_name: str, topology_path: Path) -> list[str]:
    if not isinstance(value, list):
        raise ScenarioError(f"{topology_path}: expected {field_name} to be a list")
    return [
        require_string(item, field_name=f"{field_name}[]", topology_path=topology_path)
        for item in value
    ]


def require_operation_keys(
    raw: dict[str, Any],
    *,
    allowed: set[str],
    field_name: str,
    topology_path: Path,
) -> None:
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        raise ScenarioError(
            f"{topology_path}: {field_name} has unexpected keys: {', '.join(unexpected)}"
        )


def optional_string(
    raw: dict[str, Any],
    key: str,
    *,
    field_name: str,
    topology_path: Path,
) -> str:
    value = raw.get(key)
    if value is None:
        return ""
    return require_string(
        value,
        field_name=f"{field_name}.{key}",
        topology_path=topology_path,
    )


def require_defaults(value: Any, *, topology_path: Path) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{topology_path}: expected defaults to be an object")

    normalized: dict[str, str] = {}
    for key, raw_value in value.items():
        key = require_string(key, field_name="defaults key", topology_path=topology_path)
        if not key.replace("_", "a").isalnum() or key[0].isdigit():
            raise ScenarioError(f"{topology_path}: invalid defaults key {key!r}")
        normalized[key] = require_string(
            raw_value,
            field_name=f"defaults.{key}",
            topology_path=topology_path,
        )
    return normalized


def parse_topology_roles(raw_roles: Any, *, topology_path: Path) -> dict[str, TopologyRoleSpec]:
    if raw_roles is None:
        return {}
    if not isinstance(raw_roles, dict):
        raise ScenarioError(f"{topology_path}: expected roles to be an object")

    roles: dict[str, TopologyRoleSpec] = {}
    for role_name, raw_role in raw_roles.items():
        if not isinstance(role_name, str) or not role_name:
            raise ScenarioError(f"{topology_path}: expected non-empty string role names")
        if not isinstance(raw_role, dict):
            raise ScenarioError(f"{topology_path}: role {role_name!r} must be an object")
        require_operation_keys(
            raw_role,
            allowed={"namespace"},
            field_name=f"topology role {role_name!r}",
            topology_path=topology_path,
        )
        roles[role_name] = TopologyRoleSpec(
            name=role_name,
            namespace=require_string(
                raw_role.get("namespace"),
                field_name=f"roles.{role_name}.namespace",
                topology_path=topology_path,
            ),
        )
    return roles


def normalize_operation(topology_path: Path, index: int, raw: Any) -> tuple[str, ...]:
    field_name = f"operations[{index}]"
    if not isinstance(raw, dict):
        raise ScenarioError(f"{topology_path}: expected {field_name} to be an object")

    op_type = require_string(
        raw.get("type"),
        field_name=f"{field_name}.type",
        topology_path=topology_path,
    )
    if op_type == "set-loopbacks-up":
        require_operation_keys(
            raw,
            allowed={"type", "namespaces"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            *require_string_list(
                raw.get("namespaces"),
                field_name=f"{field_name}.namespaces",
                topology_path=topology_path,
            ),
        )
    if op_type == "connect-veth":
        require_operation_keys(
            raw,
            allowed={"type", "ns_a", "iface_a", "ns_b", "iface_b"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns_a"), field_name=f"{field_name}.ns_a", topology_path=topology_path),
            require_string(raw.get("iface_a"), field_name=f"{field_name}.iface_a", topology_path=topology_path),
            require_string(raw.get("ns_b"), field_name=f"{field_name}.ns_b", topology_path=topology_path),
            require_string(raw.get("iface_b"), field_name=f"{field_name}.iface_b", topology_path=topology_path),
        )
    if op_type == "configure-ipv4-interface":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "iface", "cidr"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(raw.get("iface"), field_name=f"{field_name}.iface", topology_path=topology_path),
            require_string(raw.get("cidr"), field_name=f"{field_name}.cidr", topology_path=topology_path),
        )
    if op_type == "configure-ipv6-interface":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "iface", "cidr"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(raw.get("iface"), field_name=f"{field_name}.iface", topology_path=topology_path),
            require_string(raw.get("cidr"), field_name=f"{field_name}.cidr", topology_path=topology_path),
        )
    if op_type == "add-default-route":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "via", "dev", "metric"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(raw.get("via"), field_name=f"{field_name}.via", topology_path=topology_path),
            optional_string(raw, "dev", field_name=field_name, topology_path=topology_path),
            optional_string(raw, "metric", field_name=field_name, topology_path=topology_path),
        )
    if op_type == "add-ipv6-default-route":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "via", "dev", "metric"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(raw.get("via"), field_name=f"{field_name}.via", topology_path=topology_path),
            optional_string(raw, "dev", field_name=field_name, topology_path=topology_path),
            optional_string(raw, "metric", field_name=field_name, topology_path=topology_path),
        )
    if op_type == "add-device-route":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "destination", "dev", "metric"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(
                raw.get("destination"),
                field_name=f"{field_name}.destination",
                topology_path=topology_path,
            ),
            require_string(raw.get("dev"), field_name=f"{field_name}.dev", topology_path=topology_path),
            optional_string(raw, "metric", field_name=field_name, topology_path=topology_path),
        )
    if op_type == "add-ipv6-route":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "destination", "via", "dev", "metric"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(
                raw.get("destination"),
                field_name=f"{field_name}.destination",
                topology_path=topology_path,
            ),
            optional_string(raw, "via", field_name=field_name, topology_path=topology_path),
            optional_string(raw, "dev", field_name=field_name, topology_path=topology_path),
            optional_string(raw, "metric", field_name=field_name, topology_path=topology_path),
        )
    if op_type == "setup-basic-nat-router":
        require_operation_keys(
            raw,
            allowed={"type", "ns", "lan_iface", "wan_iface"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
            require_string(
                raw.get("lan_iface"),
                field_name=f"{field_name}.lan_iface",
                topology_path=topology_path,
            ),
            require_string(
                raw.get("wan_iface"),
                field_name=f"{field_name}.wan_iface",
                topology_path=topology_path,
            ),
        )
    if op_type == "setup-basic-ipv6-router":
        require_operation_keys(
            raw,
            allowed={"type", "ns"},
            field_name=field_name,
            topology_path=topology_path,
        )
        return (
            op_type,
            require_string(raw.get("ns"), field_name=f"{field_name}.ns", topology_path=topology_path),
        )

    raise ScenarioError(f"{topology_path}: unsupported operation type {op_type!r}")


def load_topology_file(topology_path: Path, *, expected_name: str | None = None) -> TopologySpec:
    if not topology_path.is_file():
        raise ScenarioError(f"Topology file not found: {topology_path}")

    try:
        data = json.loads(topology_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"{topology_path}: invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ScenarioError(f"{topology_path}: topology file must contain a JSON object")

    actual_name = require_string(data.get("name"), field_name="name", topology_path=topology_path)
    if expected_name is not None and actual_name != expected_name:
        raise ScenarioError(
            f"{topology_path}: topology name {actual_name!r} does not match expected {expected_name!r}"
        )

    operations = data.get("operations")
    if not isinstance(operations, list):
        raise ScenarioError(f"{topology_path}: expected operations to be a list")

    return TopologySpec(
        name=actual_name,
        description=require_string(
            data.get("description"),
            field_name="description",
            topology_path=topology_path,
        ),
        path=topology_path,
        defaults=require_defaults(data.get("defaults"), topology_path=topology_path),
        roles=parse_topology_roles(data.get("roles"), topology_path=topology_path),
        namespaces=tuple(
            require_string_list(
                data.get("namespaces"),
                field_name="namespaces",
                topology_path=topology_path,
            )
        ),
        operations=tuple(
            normalize_operation(topology_path, index, raw_operation)
            for index, raw_operation in enumerate(operations)
        ),
    )


def load_topology(topology_name: str) -> TopologySpec:
    return load_topology_file(
        TOPOLOGY_DIR / f"{topology_name}.json",
        expected_name=topology_name,
    )


def emit_topology_action_lines(topology: TopologySpec, action: str) -> list[str]:
    if action == "defaults":
        return [f"{key}\t{value}" for key, value in topology.defaults.items()]
    if action == "namespaces":
        return list(topology.namespaces)
    if action == "operations":
        return ["\t".join(operation) for operation in topology.operations]
    raise ScenarioError(f"Unsupported topology action: {action}")
