from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lib.core.models import FixtureSpec, ScenarioError, TopologyRoleSpec
from lib.core.paths import FIXTURE_DIR
from lib.core.util import slugify


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


def render_variables(
    raw_variables: Any,
    variables: dict[str, str],
    *,
    fixture_path: Path,
) -> dict[str, str]:
    result = dict(variables)
    for key, raw_value in require_object(
        raw_variables,
        field_name="expand.selectors[].vars",
        fixture_path=fixture_path,
    ).items():
        key = require_string(key, field_name="vars key", fixture_path=fixture_path)
        value = require_string(
            raw_value,
            field_name=f"vars.{key}",
            fixture_path=fixture_path,
        )
        result[key] = render_template(value, result, fixture_path=fixture_path)
    return result


def render_optional_variables(
    raw_variables: Any,
    variables: dict[str, str],
    defaults: dict[str, str],
    *,
    fixture_path: Path,
) -> dict[str, str]:
    result = dict(variables)
    for key, raw_spec in require_object(
        raw_variables,
        field_name="expand.selectors[].optional_vars",
        fixture_path=fixture_path,
    ).items():
        key = require_string(key, field_name="optional_vars key", fixture_path=fixture_path)
        spec = require_object(
            raw_spec,
            field_name=f"optional_vars.{key}",
            fixture_path=fixture_path,
        )
        reject_unsupported_fields(
            spec,
            allowed={"value", "required_defaults"},
            field_name=f"optional_vars.{key}",
            fixture_path=fixture_path,
        )
        if not validate_required_defaults(
            spec.get("required_defaults"),
            result,
            defaults,
            fixture_path=fixture_path,
        ):
            continue
        value = require_string(
            spec.get("value"),
            field_name=f"optional_vars.{key}.value",
            fixture_path=fixture_path,
        )
        result[key] = render_template(value, result, fixture_path=fixture_path)
    return result


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


def selector_variables(
    role_name: str,
    raw_selector: Any,
    *,
    fixture_path: Path,
) -> dict[str, str] | None:
    selector = require_object(
        raw_selector,
        field_name="expand.selectors[]",
        fixture_path=fixture_path,
    )
    reject_unsupported_fields(
        selector,
        allowed={"role", "role_regex", "vars", "optional_vars"},
        field_name="expand.selectors[]",
        fixture_path=fixture_path,
    )

    exact_role = selector.get("role")
    role_regex = selector.get("role_regex")
    if exact_role is not None and role_regex is not None:
        raise ScenarioError(
            f"{fixture_path}: expand.selectors[] must use either role or role_regex, not both"
        )

    variables: dict[str, str] = {}
    if exact_role is not None:
        if role_name != require_string(
            exact_role,
            field_name="expand.selectors[].role",
            fixture_path=fixture_path,
        ):
            return None
    elif role_regex is not None:
        pattern = require_string(
            role_regex,
            field_name="expand.selectors[].role_regex",
            fixture_path=fixture_path,
        )
        try:
            match = re.fullmatch(pattern, role_name)
        except re.error as exc:
            raise ScenarioError(
                f"{fixture_path}: invalid role_regex {pattern!r}: {exc}"
            ) from exc
        if match is None:
            return None
        for index, group in enumerate(match.groups(), start=1):
            variables[f"match_{index}"] = group
            variables[f"match_{index}_upper"] = group.upper()
            variables[f"match_{index}_lower"] = group.lower()
    else:
        raise ScenarioError(
            f"{fixture_path}: expand.selectors[] requires role or role_regex"
        )

    return variables


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


def role_candidates(
    raw_template: dict[str, Any],
    raw_expand: dict[str, Any],
    *,
    amount: int,
    defaults: dict[str, str],
    roles: dict[str, TopologyRoleSpec],
    fixture_path: Path,
) -> list[FixtureSpec]:
    selectors = raw_expand.get("selectors")
    if not isinstance(selectors, list) or not selectors:
        raise ScenarioError(f"{fixture_path}: expand.selectors must be a non-empty list")

    fixtures: list[FixtureSpec] = []
    for role_name in roles:
        selector_match: dict[str, str] | None = None
        raw_selector_match: Any = None
        for raw_selector in selectors:
            selector_match = selector_variables(
                role_name,
                raw_selector,
                fixture_path=fixture_path,
            )
            if selector_match is not None:
                raw_selector_match = raw_selector
                break
        if selector_match is None:
            continue

        variables = {
            "type": require_string(raw_template.get("type"), field_name="type", fixture_path=fixture_path),
            "role": role_name,
            "role_slug": slugify(role_name.replace("_", "-")),
            "index": str(len(fixtures) + 1),
            **selector_match,
        }
        variables = render_variables(
            require_object(
                raw_selector_match,
                field_name="expand.selectors[]",
                fixture_path=fixture_path,
            ).get("vars"),
            variables,
            fixture_path=fixture_path,
        )
        variables = render_optional_variables(
            require_object(
                raw_selector_match,
                field_name="expand.selectors[]",
                fixture_path=fixture_path,
            ).get("optional_vars"),
            variables,
            defaults,
            fixture_path=fixture_path,
        )
        if not validate_required_defaults(
            raw_expand.get("required_defaults"),
            variables,
            defaults,
            fixture_path=fixture_path,
        ):
            continue
        if not validate_required_defaults(
            raw_template.get("required_defaults"),
            variables,
            defaults,
            fixture_path=fixture_path,
        ):
            continue
        fixtures.append(build_fixture(raw_template, variables, fixture_path=fixture_path))
        if len(fixtures) == amount:
            break
    return fixtures


def expand_role_fixtures(
    raw_template: dict[str, Any],
    raw_expand: dict[str, Any],
    *,
    amount: int,
    defaults: dict[str, str],
    roles: dict[str, TopologyRoleSpec],
    fixture_type: str,
    topology_path: Path,
    fixture_path: Path,
) -> tuple[FixtureSpec, ...]:
    fixtures = role_candidates(
        raw_template,
        raw_expand,
        amount=amount,
        defaults=defaults,
        roles=roles,
        fixture_path=fixture_path,
    )
    if len(fixtures) < amount:
        raise ScenarioError(
            f"{topology_path}: fixture type {fixture_type!r} amount={amount} "
            f"matched only {len(fixtures)} topology role(s)"
        )
    return tuple(fixtures)


def expand_fixture_template(
    *,
    fixture_type: str,
    amount: int,
    defaults: dict[str, str],
    roles: dict[str, TopologyRoleSpec],
    topology_path: Path,
) -> tuple[FixtureSpec, ...]:
    fixture_path, raw_template = load_fixture_template(fixture_type)
    raw_expand = require_object(raw_template.get("expand"), field_name="expand", fixture_path=fixture_path)
    if not raw_expand:
        return expand_static_fixture(
            raw_template,
            amount=amount,
            defaults=defaults,
            fixture_type=fixture_type,
            topology_path=topology_path,
            fixture_path=fixture_path,
        )
    reject_unsupported_fields(
        raw_expand,
        allowed={"source", "selectors", "required_defaults"},
        field_name="expand",
        fixture_path=fixture_path,
    )
    source = require_string(raw_expand.get("source"), field_name="expand.source", fixture_path=fixture_path)
    if source == "roles":
        return expand_role_fixtures(
            raw_template,
            raw_expand,
            amount=amount,
            defaults=defaults,
            roles=roles,
            fixture_type=fixture_type,
            topology_path=topology_path,
            fixture_path=fixture_path,
        )
    raise ScenarioError(f"{fixture_path}: unsupported fixture expansion source {source!r}")
