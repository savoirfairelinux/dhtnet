from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lib.core.util import now_ms
from lib.tools.probe_runner import (
    ActionOutcome,
    ActionSchema,
    ProbeSequenceState,
    action_id,
    action_timeout_s,
    capture_path,
    optional_string,
    record_assertion,
    register_probe_action,
    require_string,
)

MAPPING_DPORT_RE = re.compile(r"\b(tcp|udp)\s+dport\s+(\d+)\b")
DNAT_TARGET_RE = re.compile(r"\bdnat to (?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d+)\b")


@dataclass(frozen=True)
class PortMapping:
    protocol: str
    external_port: str
    target_ip: str
    target_port: str
    line: str


def namespace_ipv4_addresses(namespace: str) -> set[str]:
    completed = subprocess.run(
        ["ip", "-n", namespace, "-o", "-4", "addr", "show"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return set()
    addresses: set[str] = set()
    for token in completed.stdout.split():
        if "/" in token and token.count(".") == 3:
            addresses.add(token.split("/", 1)[0])
    return addresses


def mapped_ports(router_namespace: str) -> tuple[list[PortMapping], str]:
    completed = subprocess.run(
        ["ip", "netns", "exec", router_namespace, "nft", "list", "chain", "ip", "miniupnpd", "prerouting"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return [], completed.stderr
    mappings: dict[tuple[str, str], PortMapping] = {}
    for line in completed.stdout.splitlines():
        dport_match = MAPPING_DPORT_RE.search(line)
        if not dport_match:
            continue
        dnat_match = DNAT_TARGET_RE.search(line)
        mapping = PortMapping(
            protocol=dport_match.group(1).lower(),
            external_port=dport_match.group(2),
            target_ip=dnat_match.group(1) if dnat_match and dnat_match.group(1) else "",
            target_port=dnat_match.group(2) if dnat_match else "",
            line=line.strip(),
        )
        mappings[(mapping.protocol, mapping.external_port)] = mapping
    return sorted(mappings.values(), key=lambda item: int(item.external_port)), completed.stdout


def session_srflx_ports(capture_path: Path, router_external_ip: str) -> set[tuple[str, str]]:
    if not capture_path.is_file():
        return set()
    ports: set[tuple[str, str]] = set()
    for line in capture_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if " typ srflx" not in line or router_external_ip not in line:
            continue
        parts = line.split()
        for index, token in enumerate(parts):
            if token.upper() in {"TCP", "UDP"} and index + 3 < len(parts) and parts[index + 2] == router_external_ip:
                ports.add((token.lower(), parts[index + 3]))
    return ports


def run_assert_upnp_mappings(action: dict[str, Any], state: ProbeSequenceState) -> ActionOutcome:
    started_ms = now_ms()
    name = action_id(action)
    router_namespace = require_string(action.get("router_namespace"), field_name="router_namespace", state=state)
    target_namespace = optional_string(action, "target_namespace", state, default="")
    router_external_ip = optional_string(action, "router_external_ip", state, default="")
    session_capture = optional_string(action, "session_capture", state, default="")
    timeout_s = action_timeout_s(action, 20)
    destination = optional_string(action, "capture", state, default="mapped-ports.txt")
    output_name = optional_string(action, "output", state, default="mapped_ports")

    deadline = time.monotonic() + timeout_s
    mappings: list[PortMapping] = []
    target_ips: set[str] = set()
    session_ports: set[tuple[str, str]] = set()
    session_capture_path = Path(session_capture) if session_capture else None
    requires_session_correlation = session_capture_path is not None and bool(router_external_ip)
    while time.monotonic() <= deadline:
        mappings, _raw = mapped_ports(router_namespace)
        if target_namespace:
            target_ips = namespace_ipv4_addresses(target_namespace)
        if session_capture_path is not None and router_external_ip:
            session_ports = session_srflx_ports(session_capture_path, router_external_ip)
        target_matches = (
            not target_namespace
            or any(mapping.target_ip in target_ips for mapping in mappings)
        )
        session_matches = (
            not requires_session_correlation
            or (
                bool(session_ports)
                and any((mapping.protocol, mapping.external_port) in session_ports for mapping in mappings)
            )
        )
        if mappings and target_matches and session_matches:
            break
        time.sleep(1)

    output_path = capture_path(state.recorder, destination)
    output_lines = [
        json.dumps(
            {
                "protocol": mapping.protocol,
                "external_port": mapping.external_port,
                "target_ip": mapping.target_ip,
                "target_port": mapping.target_port,
                "line": mapping.line,
            },
            sort_keys=True,
        )
        for mapping in mappings
    ]
    output_path.write_text("\n".join(output_lines) + ("\n" if output_lines else ""), encoding="utf-8")
    state.recorder.record_command_capture("mapped UPnP ports", "command-output", output_path)
    state.outputs[output_name] = [mapping.external_port for mapping in mappings]

    router_ips = namespace_ipv4_addresses(router_namespace)
    if router_external_ip and router_external_ip not in router_ips:
        details = f"Router namespace {router_namespace} does not have expected external IP {router_external_ip}."
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    if requires_session_correlation and not session_ports:
        details = (
            "No server-reflexive ICE candidate ports for the router external IP were parsed from "
            f"{session_capture_path}. Mappings: {[mapping.line for mapping in mappings]}."
        )
        record_assertion(state.recorder, name, "failed", started_ms, details)
        return ActionOutcome(False, details)

    if mappings and not target_namespace:
        matching_mappings = [
            mapping
            for mapping in mappings
            if not requires_session_correlation or (mapping.protocol, mapping.external_port) in session_ports
        ]
        if matching_mappings:
            state.recorder.metric("mapped_port_count", len(mappings))
            details = f"At least one UPnP mapping exists on router external IP {router_external_ip or '<unspecified>'}."
            record_assertion(state.recorder, name, "passed", started_ms, details)
            return ActionOutcome(True, details)

    matching_mappings = [
        mapping
        for mapping in mappings
        if mapping.target_ip in target_ips
        and (not requires_session_correlation or (mapping.protocol, mapping.external_port) in session_ports)
    ]
    if matching_mappings:
        state.recorder.metric("mapped_port_count", len(mappings))
        details = (
            "Observed UPnP mapping(s) whose DNAT target is the active target namespace and whose "
            f"external port appears in the dhtnet session candidates: "
            f"{[f'{mapping.protocol}/{mapping.external_port}' for mapping in matching_mappings]}."
        )
        record_assertion(state.recorder, name, "passed", started_ms, details)
        return ActionOutcome(True, details)

    details = (
        "No UPnP mapping for the active dhtnet session was observed. "
        f"Target IPs: {sorted(target_ips)}. Session srflx ports: {sorted(session_ports)}. "
        f"Mappings: {[mapping.line for mapping in mappings]}."
    )
    record_assertion(state.recorder, name, "failed", started_ms, details)
    return ActionOutcome(False, details)


def register_actions() -> None:
    register_probe_action(
        "assert_upnp_mappings",
        ActionSchema(
            required=frozenset({"router_namespace"}),
            optional=frozenset({"target_namespace", "capture", "output", "router_external_ip", "session_capture", "timeout_s"}),
        ),
        run_assert_upnp_mappings,
    )
