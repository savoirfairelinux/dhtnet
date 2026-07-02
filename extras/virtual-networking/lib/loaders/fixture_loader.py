from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.core.models import FixtureSpec, ScenarioError, TopologyRoleSpec
from lib.core.paths import FIXTURE_DIR


class PartialTemplateContext(dict[str, str]):
    def __init__(self, values: dict[str, str], *, missing_value: str | None = None) -> None:
        super().__init__(values)
        self.missing_value = missing_value

    def __missing__(self, key: str) -> str:
        if self.missing_value is not None:
            return self.missing_value
        return "{" + key + "}"


def require_string(value: Any, *, field_name: str, fixture_path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{fixture_path}: expected non-empty string for {field_name}")
    if any(char in value for char in ("\n", "\r", "\t")):
        raise ScenarioError(f"{fixture_path}: {field_name} must not contain tabs or newlines")
    return value


def require_string_list(value: Any, *, field_name: str, fixture_path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ScenarioError(f"{fixture_path}: expected {field_name} to be a list")
    return [
        require_string(item, field_name=f"{field_name}[]", fixture_path=fixture_path)
        for item in value
    ]


def require_object(value: Any, *, field_name: str, fixture_path: Path) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScenarioError(f"{fixture_path}: expected {field_name} to be an object")
    return dict(value)


def reject_unsupported_fields(
    raw: dict[str, Any],
    *,
    allowed: set[str],
    field_name: str,
    fixture_path: Path,
) -> None:
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        raise ScenarioError(
            f"{fixture_path}: {field_name} has unexpected keys: {', '.join(unexpected)}"
        )


def render_template(
    template: str,
    variables: dict[str, str],
    *,
    fixture_path: Path,
    missing_value: str | None = None,
) -> str:
    try:
        return template.format_map(
            PartialTemplateContext(variables, missing_value=missing_value)
        )
    except ValueError as exc:
        raise ScenarioError(f"{fixture_path}: invalid template {template!r}: {exc}") from exc


def render_value(
    value: Any,
    variables: dict[str, str],
    *,
    fixture_path: Path,
    missing_value: str | None = None,
) -> Any:
    if isinstance(value, str):
        return render_template(
            value,
            variables,
            fixture_path=fixture_path,
            missing_value=missing_value,
        )
    if isinstance(value, list):
        return [
            render_value(
                item,
                variables,
                fixture_path=fixture_path,
                missing_value=missing_value,
            )
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: render_value(
                item,
                variables,
                fixture_path=fixture_path,
                missing_value=missing_value,
            )
            for key, item in value.items()
        }
    return value


def validate_required_defaults(
    raw_required_defaults: Any,
    variables: dict[str, str],
    defaults: dict[str, str],
    *,
    fixture_path: Path,
) -> bool:
    for raw_default in require_string_list(
        raw_required_defaults,
        field_name="required_defaults",
        fixture_path=fixture_path,
    ):
        default_name = render_template(raw_default, variables, fixture_path=fixture_path)
        if default_name not in defaults:
            return False
    return True


def load_fixture_template(fixture_type: str) -> tuple[Path, dict[str, Any]]:
    fixture_path = FIXTURE_DIR / f"{fixture_type}.json"
    if not fixture_path.is_file():
        raise ScenarioError(f"Fixture template file not found: {fixture_path}")
    try:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"{fixture_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScenarioError(f"{fixture_path}: fixture template must contain a JSON object")
    reject_unsupported_fields(
        data,
        allowed={
            "type",
            "description",
            "kind",
            "name",
            "required_defaults",
            "expand",
            "runtime",
        },
        field_name="fixture template",
        fixture_path=fixture_path,
    )
    actual_type = require_string(data.get("type"), field_name="type", fixture_path=fixture_path)
    if actual_type != fixture_type:
        raise ScenarioError(
            f"{fixture_path}: fixture template type {actual_type!r} does not match "
            f"requested type {fixture_type!r}"
        )
    return fixture_path, data


def build_fixture(
    raw_template: dict[str, Any],
    variables: dict[str, str],
    *,
    fixture_path: Path,
) -> FixtureSpec:
    name = render_template(
        require_string(raw_template.get("name"), field_name="name", fixture_path=fixture_path),
        variables,
        fixture_path=fixture_path,
    )
    fixture_variables = dict(variables)
    fixture_variables["name"] = name
    options = render_value(
        require_object(raw_template.get("runtime"), field_name="runtime", fixture_path=fixture_path),
        fixture_variables,
        fixture_path=fixture_path,
    )
    return FixtureSpec(
        name=name,
        description=render_template(
            require_string(
                raw_template.get("description"),
                field_name="description",
                fixture_path=fixture_path,
            ),
            fixture_variables,
            fixture_path=fixture_path,
        ),
        kind=render_template(
            require_string(raw_template.get("kind"), field_name="kind", fixture_path=fixture_path),
            fixture_variables,
            fixture_path=fixture_path,
        ),
        options=options,
        path=fixture_path,
    )


def expand_static_fixture(
    raw_template: dict[str, Any],
    *,
    amount: int,
    defaults: dict[str, str],
    fixture_type: str,
    topology_path: Path,
    fixture_path: Path,
) -> tuple[FixtureSpec, ...]:
    if amount != 1:
        raise ScenarioError(f"{topology_path}: fixture type {fixture_type!r} supports only amount=1")
    variables = {"type": fixture_type, "index": "1"}
    if not validate_required_defaults(
        raw_template.get("required_defaults"),
        variables,
        defaults,
        fixture_path=fixture_path,
    ):
        raise ScenarioError(
            f"{topology_path}: fixture type {fixture_type!r} is missing required topology defaults"
        )
    return (build_fixture(raw_template, variables, fixture_path=fixture_path),)


def expand_fixture_template(
    *,
    fixture_type: str,
    amount: int,
    defaults: dict[str, str],
    roles: dict[str, TopologyRoleSpec],
    topology_path: Path,
) -> tuple[FixtureSpec, ...]:
    del roles
    fixture_path, raw_template = load_fixture_template(fixture_type)
    raw_expand = require_object(raw_template.get("expand"), field_name="expand", fixture_path=fixture_path)
    if raw_expand:
        raise ScenarioError(f"{fixture_path}: fixture template requires role expansion support")
    return expand_static_fixture(
        raw_template,
        amount=amount,
        defaults=defaults,
        fixture_type=fixture_type,
        topology_path=topology_path,
        fixture_path=fixture_path,
    )
