from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.core.models import (
    ActorSpec,
    FixtureSpec,
    ProbeSpec,
    ScenarioError,
    ScenarioSpec,
    StepSpec,
    TopologySpec,
)
from lib.core.paths import DEFAULT_STATE_ROOT, PROBE_DIR, ROOT
from .topology_loader import load_topology
from lib.core.util import namespace_prefix, slugify
from lib.tools.probe_runner import validate_probe_action

SCENARIO_FIELDS = frozenset(
    {
        "name",
        "description",
        "topology",
        "fixtures",
        "actors",
        "steps",
        "notes",
    }
)

PROBE_STEP_FIELDS = frozenset(
    {
        "name",
        "probe",
        "inputs",
        "allow_failure",
    }
)
ACTOR_FIELDS = frozenset({"name", "kind", "role", "wait_s", "bootstrap_fixture"})
FIXTURE_FIELDS = frozenset({"name", "description", "kind", "options"})
PROBE_FIELDS = frozenset(
    {
        "name",
        "description",
        "required_inputs",
        "probe_sequence",
    }
)
def require_string(value: Any, *, field_name: str, scenario_path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{scenario_path}: expected non-empty string for {field_name}")
    return value


def require_optional_string(value: Any, *, field_name: str, scenario_path: Path) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{scenario_path}: expected a non-empty string for {field_name} when present")
    return value


def require_string_list(value: Any, *, field_name: str, scenario_path: Path) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScenarioError(f"{scenario_path}: expected a string list for {field_name}")
    return list(value)


def require_optional_string_list(value: Any, *, field_name: str, scenario_path: Path) -> list[str]:
    if value is None:
        return []
    return require_string_list(value, field_name=field_name, scenario_path=scenario_path)


def require_nonnegative_float(value: Any, *, field_name: str, scenario_path: Path) -> float:
    if not isinstance(value, (int, float)):
        raise ScenarioError(f"{scenario_path}: expected a number for {field_name}")
    if value < 0:
        raise ScenarioError(f"{scenario_path}: expected a non-negative number for {field_name}")
    return float(value)


def require_optional_bool(value: Any, *, field_name: str, scenario_path: Path) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ScenarioError(f"{scenario_path}: expected a JSON boolean for {field_name}")
    return value


def format_field_names(fields: list[str] | frozenset[str]) -> str:
    return ", ".join(repr(field) for field in sorted(fields))


def require_object(value: Any, *, field_name: str, object_path: Path) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScenarioError(f"{object_path}: expected {field_name} to be an object")
    return dict(value)


def reject_unsupported_fields(
    raw: dict[str, Any],
    *,
    allowed_fields: frozenset[str],
    context: str,
    scenario_path: Path,
) -> None:
    unsupported = sorted(set(raw) - allowed_fields)
    if not unsupported:
        return
    raise ScenarioError(
        f"{scenario_path}, {context} has unsupported field(s): {unsupported}. "
        f"This runner currently accepts only the composition fields {format_field_names(allowed_fields)}."
    )


def role_context_key(role_name: str, field_name: str) -> str:
    def normalize(value: str) -> str:
        cleaned = "".join(char if char.isalnum() else "_" for char in value).strip("_").upper()
        return cleaned or "VALUE"

    return f"ROLE_{normalize(role_name)}_{normalize(field_name)}"


def actor_context_key(actor_name: str, field_name: str) -> str:
    actor_part = slugify(actor_name).replace("-", "_").upper()
    if not field_name:
        return f"ACTOR_{actor_part}_"
    return f"ACTOR_{actor_part}_{slugify(field_name).replace('-', '_').upper()}"


def fixture_context_key(fixture_name: str, field_name: str) -> str:
    fixture_part = slugify(fixture_name).replace("-", "_").upper()
    if not field_name:
        return f"FIXTURE_{fixture_part}_"
    return f"FIXTURE_{fixture_part}_{slugify(field_name).replace('-', '_').upper()}"


def probe_context_key(step_name: str, field_name: str) -> str:
    probe_part = slugify(step_name).replace("-", "_").upper()
    if not field_name:
        return f"PROBE_{probe_part}_"
    return f"PROBE_{probe_part}_{slugify(field_name).replace('-', '_').upper()}"


def ensure_role_exists(role_name: str, *, topology: TopologySpec, object_path: Path, field_name: str) -> str:
    if role_name not in topology.roles:
        raise ScenarioError(
            f"{object_path}: {field_name} references unknown topology role {role_name!r} for topology {topology.name!r}"
        )
    return role_name


def resolve_text(template: str, context: dict[str, str], *, scenario_name: str) -> str:
    try:
        return template.format_map(context)
    except KeyError as exc:
        missing = exc.args[0]
        raise ScenarioError(
            f"Scenario {scenario_name!r} references unknown placeholder {missing!r} in {template!r}"
        ) from exc


def resolve_value(value: Any, context: dict[str, str], *, scenario_name: str) -> Any:
    if isinstance(value, str):
        return resolve_text(value, context, scenario_name=scenario_name)
    if isinstance(value, list):
        return [resolve_value(item, context, scenario_name=scenario_name) for item in value]
    if isinstance(value, dict):
        return {key: resolve_value(item, context, scenario_name=scenario_name) for key, item in value.items()}
    return value


def context_set_scalar(context: dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        context[key] = "1" if value else "0"
    else:
        context[key] = str(value)


def update_context_from_outputs(context: dict[str, str], prefix_key: str, outputs: dict[str, Any]) -> None:
    for key, value in outputs.items():
        normalized_key = slugify(str(key)).replace("-", "_").upper()
        context_set_scalar(context, prefix_key + normalized_key, value)


def fixture_record_payload(
    fixture: FixtureSpec,
    outputs: dict[str, Any],
    artifacts: dict[str, str],
    options: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": fixture.name,
        "kind": fixture.kind,
        "description": fixture.description,
        "options": options,
        "outputs": outputs,
        "artifacts": artifacts,
    }


def parse_actor(raw: Any, *, scenario_path: Path, topology: TopologySpec) -> ActorSpec:
    if not isinstance(raw, dict):
        raise ScenarioError(f"{scenario_path}: actors entries must be objects")
    actor_context = f"actor {raw['name']!r}" if isinstance(raw.get("name"), str) and raw.get("name") else "actors[] entry"
    reject_unsupported_fields(
        raw,
        allowed_fields=ACTOR_FIELDS,
        context=actor_context,
        scenario_path=scenario_path,
    )
    kind = require_string(raw.get("kind"), field_name="actors[].kind", scenario_path=scenario_path)
    if kind not in {"dsh-listener"}:
        raise ScenarioError(f"{scenario_path}: unsupported actor kind {kind!r}")
    role = ensure_role_exists(
        require_string(raw.get("role"), field_name="actors[].role", scenario_path=scenario_path),
        topology=topology,
        object_path=scenario_path,
        field_name="actors[].role",
    )
    return ActorSpec(
        name=require_string(raw.get("name"), field_name="actors[].name", scenario_path=scenario_path),
        kind=kind,
        role=role,
        wait_s=require_nonnegative_float(raw.get("wait_s", 0.0), field_name="actors[].wait_s", scenario_path=scenario_path),
        bootstrap_fixture=require_optional_string(
            raw.get("bootstrap_fixture"),
            field_name="actors[].bootstrap_fixture",
            scenario_path=scenario_path,
        ),
    )


def parse_step(raw: Any, *, scenario_path: Path) -> StepSpec:
    if not isinstance(raw, dict):
        raise ScenarioError(f"{scenario_path}: steps must contain objects")
    step_context = f"step {raw['name']!r}" if isinstance(raw.get("name"), str) and raw.get("name") else "steps[] entry"
    reject_unsupported_fields(
        raw,
        allowed_fields=PROBE_STEP_FIELDS,
        context=step_context,
        scenario_path=scenario_path,
    )
    name = require_string(raw.get("name"), field_name="steps[].name", scenario_path=scenario_path)
    probe_name = require_string(raw.get("probe"), field_name="steps[].probe", scenario_path=scenario_path)
    inputs = require_object(raw.get("inputs"), field_name="steps[].inputs", object_path=scenario_path)
    return StepSpec(
        name=name,
        inputs=inputs,
        allow_failure=require_optional_bool(
            raw.get("allow_failure"),
            field_name="steps[].allow_failure",
            scenario_path=scenario_path,
        ),
        probe=probe_name,
    )


def load_scenario_data(data: dict[str, Any], *, path: Path) -> ScenarioSpec:
    reject_unsupported_fields(
        data,
        allowed_fields=SCENARIO_FIELDS,
        context="scenario",
        scenario_path=path,
    )
    topology_name = require_string(data.get("topology"), field_name="topology", scenario_path=path)
    topology = load_topology(topology_name)
    notes = data.get("notes", [])
    if not isinstance(notes, list) or not all(isinstance(item, str) for item in notes):
        raise ScenarioError(f"{path}: notes must be a string list")
    steps = data.get("steps", [])
    if not isinstance(steps, list):
        raise ScenarioError(f"{path}: steps must be a list")
    fixtures = require_optional_string_list(data.get("fixtures"), field_name="fixtures", scenario_path=path)
    actors_raw = data.get("actors", [])
    if actors_raw is None:
        actors_raw = []
    if not isinstance(actors_raw, list):
        raise ScenarioError(f"{path}: actors must be a list when present")
    parsed_steps = [parse_step(item, scenario_path=path) for item in steps]
    actors = [parse_actor(item, scenario_path=path, topology=topology) for item in actors_raw]

    return ScenarioSpec(
        name=require_string(data.get("name"), field_name="name", scenario_path=path),
        description=require_string(data.get("description"), field_name="description", scenario_path=path),
        topology=topology_name,
        steps=parsed_steps,
        notes=list(notes),
        path=path,
        fixtures=fixtures,
        actors=actors,
    )


def load_scenario(path: Path) -> ScenarioSpec:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: scenario file must contain a JSON object")
    return load_scenario_data(data, path=path)


def load_scenarios(scenario_dir: Path) -> dict[str, ScenarioSpec]:
    scenarios: dict[str, ScenarioSpec] = {}
    for path in sorted(scenario_dir.glob("*.json")):
        scenario = load_scenario(path)
        if scenario.name in scenarios:
            raise ScenarioError(f"Duplicate scenario name {scenario.name!r} in {path}")
        scenarios[scenario.name] = scenario
    return scenarios


def parse_fixture(path: Path) -> FixtureSpec:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: fixture file must contain a JSON object")
    reject_unsupported_fields(
        data,
        allowed_fields=FIXTURE_FIELDS,
        context="fixture",
        scenario_path=path,
    )
    return FixtureSpec(
        name=require_string(data.get("name"), field_name="name", scenario_path=path),
        description=require_string(data.get("description"), field_name="description", scenario_path=path),
        kind=require_string(data.get("kind"), field_name="kind", scenario_path=path),
        options=require_object(data.get("options"), field_name="options", object_path=path),
        path=path,
    )


def load_fixtures(fixture_dir: Path) -> dict[str, FixtureSpec]:
    fixtures: dict[str, FixtureSpec] = {}
    if not fixture_dir.exists():
        return fixtures
    for path in sorted(fixture_dir.glob("*.json")):
        fixture = parse_fixture(path)
        if fixture.name in fixtures:
            raise ScenarioError(f"Duplicate fixture name {fixture.name!r} in {path}")
        fixtures[fixture.name] = fixture
    return fixtures


def parse_probe(path: Path) -> ProbeSpec:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: probe file must contain a JSON object")
    reject_unsupported_fields(
        data,
        allowed_fields=PROBE_FIELDS,
        context="probe",
        scenario_path=path,
    )
    probe_name = require_string(data.get("name"), field_name="name", scenario_path=path)
    required_inputs = tuple(require_optional_string_list(data.get("required_inputs"), field_name="required_inputs", scenario_path=path))
    raw_probe_sequence = data.get("probe_sequence", [])
    if not isinstance(raw_probe_sequence, list) or not all(isinstance(item, dict) for item in raw_probe_sequence):
        raise ScenarioError(f"{path}: expected probe_sequence to be a list of objects when present")
    probe_sequence = [dict(item) for item in raw_probe_sequence]

    if not probe_sequence:
        raise ScenarioError(f"{path}: probes require a non-empty probe_sequence list")
    for index, action in enumerate(probe_sequence):
        validate_probe_action(action, probe_name=probe_name, path=path, index=index)

    return ProbeSpec(
        name=probe_name,
        description=require_string(data.get("description"), field_name="description", scenario_path=path),
        path=path,
        required_inputs=required_inputs,
        probe_sequence=probe_sequence,
    )


def load_probes(probe_dir: Path = PROBE_DIR) -> dict[str, ProbeSpec]:
    probes: dict[str, ProbeSpec] = {}
    if not probe_dir.exists():
        return probes
    for path in sorted(probe_dir.glob("*.json")):
        probe = parse_probe(path)
        if probe.name in probes:
            raise ScenarioError(f"Duplicate probe name {probe.name!r} in {path}")
        probes[probe.name] = probe
    return probes


def apply_topology_context(context: dict[str, str], topology: TopologySpec, *, scenario_name: str) -> None:
    for key, value in topology.defaults.items():
        context.setdefault(key, value)
    for role_name, role in sorted(topology.roles.items()):
        context[role_context_key(role_name, "namespace")] = resolve_text(
            role.namespace,
            context,
            scenario_name=scenario_name,
        )


def build_scenario_context(
    scenario: ScenarioSpec,
    *,
    artifact_root: Path,
    run_id: str,
) -> tuple[TopologySpec, dict[str, str]]:
    topology = load_topology(scenario.topology)
    ns_prefix = namespace_prefix(run_id)
    context: dict[str, str] = {
        "root": str(ROOT),
        "ROOT": str(ROOT),
        "artifact_root": str(artifact_root),
        "ARTIFACT_ROOT": str(artifact_root),
        "run_id": run_id,
        "RUN_ID": run_id,
        "run_dir": str(artifact_root / run_id),
        "RUN_DIR": str(artifact_root / run_id),
        "scenario": scenario.name,
        "SCENARIO": scenario.name,
        "state_root": str(DEFAULT_STATE_ROOT),
        "STATE_ROOT": str(DEFAULT_STATE_ROOT),
        "topology_file": str(topology.path),
        "TOPOLOGY_FILE": str(topology.path),
        "namespace_prefix": ns_prefix,
        "NAMESPACE_PREFIX": ns_prefix,
    }
    for key, value in topology.defaults.items():
        if key.endswith("_NS"):
            context[key] = f"{ns_prefix}-{value}"
    apply_topology_context(context, topology, scenario_name=scenario.name)
    return topology, context


def resolved_topology_namespaces(topology: TopologySpec, context: dict[str, str], *, scenario_name: str) -> list[str]:
    return [resolve_text(namespace, context, scenario_name=scenario_name) for namespace in topology.namespaces]


def validate_step_input_binding(
    binding: Any,
    *,
    scenario: ScenarioSpec,
    topology: TopologySpec,
    actor_names: set[str],
    fixture_names: set[str],
    field_path: str,
) -> None:
    if isinstance(binding, list):
        for index, item in enumerate(binding):
            validate_step_input_binding(
                item,
                scenario=scenario,
                topology=topology,
                actor_names=actor_names,
                fixture_names=fixture_names,
                field_path=f"{field_path}[{index}]",
            )
        return
    if not isinstance(binding, dict):
        return

    source_keys = [key for key in ("role", "actor", "fixture", "context", "value") if key in binding]
    if len(source_keys) > 1:
        raise ScenarioError(f"{scenario.path}: {field_path} must reference exactly one binding source, got {source_keys}")
    if "role" in binding:
        role_name = require_string(binding["role"], field_name=field_path, scenario_path=scenario.path)
        ensure_role_exists(role_name, topology=topology, object_path=scenario.path, field_name=field_path)
        field_name = binding.get("field", "namespace")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {field_path}.field must be a non-empty string when binding a role")
        return
    if "actor" in binding:
        actor_name = require_string(binding["actor"], field_name=field_path, scenario_path=scenario.path)
        if actor_name not in actor_names:
            raise ScenarioError(f"{scenario.path}: {field_path} references unknown actor {actor_name!r}")
        field_name = binding.get("field", "namespace")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {field_path}.field must be a non-empty string when binding an actor")
        return
    if "fixture" in binding:
        fixture_name = require_string(binding["fixture"], field_name=field_path, scenario_path=scenario.path)
        if fixture_name not in fixture_names:
            raise ScenarioError(f"{scenario.path}: {field_path} references unknown fixture {fixture_name!r}")
        field_name = binding.get("field")
        if not isinstance(field_name, str) or not field_name:
            raise ScenarioError(f"{scenario.path}: {field_path}.field must be a non-empty string when binding a fixture")
        return
    if "context" in binding:
        context_name = binding["context"]
        if not isinstance(context_name, str) or not context_name:
            raise ScenarioError(f"{scenario.path}: {field_path}.context must be a non-empty string")
        return
    if "value" in binding:
        validate_step_input_binding(
            binding["value"],
            scenario=scenario,
            topology=topology,
            actor_names=actor_names,
            fixture_names=fixture_names,
            field_path=f"{field_path}.value",
        )
        return
    for key, value in binding.items():
        validate_step_input_binding(
            value,
            scenario=scenario,
            topology=topology,
            actor_names=actor_names,
            fixture_names=fixture_names,
            field_path=f"{field_path}.{key}",
        )


def validate_scenario_against_fixtures(
    scenario: ScenarioSpec,
    topology: TopologySpec,
    fixtures: dict[str, FixtureSpec],
    probes: dict[str, ProbeSpec],
) -> None:
    actor_names = {actor.name for actor in scenario.actors}
    fixture_names = set(scenario.fixtures)
    for fixture_name in scenario.fixtures:
        if fixture_name not in fixtures:
            raise ScenarioError(f"{scenario.path}: unknown fixture {fixture_name!r}")

    for actor in scenario.actors:
        ensure_role_exists(actor.role, topology=topology, object_path=scenario.path, field_name=f"actor {actor.name!r}.role")
        if actor.bootstrap_fixture and actor.bootstrap_fixture not in fixture_names:
            raise ScenarioError(
                f"{scenario.path}: actor {actor.name!r} references bootstrap_fixture {actor.bootstrap_fixture!r} "
                "which is not listed in scenario.fixtures"
            )

    for step in scenario.steps:
        if step.probe not in probes:
            raise ScenarioError(f"{scenario.path}: step {step.name!r}.probe references unknown probe {step.probe!r}")
        for input_name, binding in step.inputs.items():
            validate_step_input_binding(
                binding,
                scenario=scenario,
                topology=topology,
                actor_names=actor_names,
                fixture_names=fixture_names,
                field_path=f"step {step.name!r}.inputs.{input_name}",
            )
