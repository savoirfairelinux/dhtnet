# Adding tests to the virtual-networking harness

In this harness, a “test” is usually a **scenario** under `scenarios/*.json`. A scenario composes:

- a **topology** from `topologies/*.json`
- optional **fixtures** from `fixtures/*.json`
- optional long-running **services** backed by `lib/service_actions/`
- ordered **probe steps** using `probes/*.json`

The normal workflow goes through `run.py`.

## Start by inspecting what already exists

Before adding anything, look for the closest existing composition:

```bash
./run.py list
./run.py describe upnp-static
./run.py describe dual-access-smoke
```

Useful reference files:

- `README.md`
- `docs/baseline-scenario.md`
- `docs/result-format.md`
- `scenarios/upnp-static.json`
- `scenarios/dual-access-smoke.json`

## Choose the smallest change that fits

Use this rule of thumb:

| If you need... | Add... |
| --- | --- |
| Only a new combination of existing topology/fixtures/services/probes | a new `scenarios/*.json` file |
| A new command/check that fits existing runtime behavior | a new `probes/*.json` file, and maybe a small typed action module in `lib/probe_actions/` |
| A new router/bootstrap instance using an existing built-in fixture kind | a new `fixtures/*.json` file |
| A new network layout | a new `topologies/*.json` file |
| A new fixture kind, service readiness/output kind, or probe action type | Python/runtime changes in `lib/runtime/`, `lib/loaders/`, or `lib/probe_actions/` plus the new JSON definition(s) |

Prefer reusable pieces over one-off scenario-specific logic.

## Scenario building blocks

### Topologies

Topologies define the network shape, defaults, roles, namespaces, and operations.

Keep role names stable when they mean the same thing across labs, for example:

- `lan_node`
- `edge_router`
- `wan_client`
- `node`

That lets probes bind to intent instead of hard-coded namespace names.
Roles are the topology's semantic API: they map reusable fixture, service, and probe definitions onto the concrete namespaces in a specific lab.

The top-level `namespaces` list drives both setup namespace creation and cleanup. `operations` should only wire and configure those namespaces.

### Fixtures

Fixtures are reusable services layered onto a topology. Current built-in kinds are:

- `local-bootstrap`
- `miniupnpd`

If you only need a different instance of one of those kinds, add a new JSON file under `fixtures/`.
Fixture roles are declared through the options consumed by the fixture kind, such as `options.role` and optional discovery role fields.
For `miniupnpd`, discovery checks validate the expected external IP. The expected IP defaults to `options.ext_ip`; use `options.discovery_expected_external_ip` only when it differs, and use `options.discovery_bind_ip` for multi-uplink clients that must query a specific local address.

### Services

Services are long-running managed processes started by the runner. The current checked-in service kind is:

- `command`

Command services run an argv array inside a role namespace. Service helper
scripts live under `lib/service_actions/`; for example, existing DHTNet
scenarios use `lib/service_actions/launch-dsh-listener.sh`.

Services can use file readiness and JSON outputs that later steps consume.

### Probes

Probes are reusable step definitions in `probes/*.json`. Each probe carries an ordered `probe_sequence`
of typed actions implemented by modules under `lib/probe_actions/`, so the
actual assertions and captures stay visible in the probe file instead of disappearing into a shell wrapper.

Probe JSON composes typed actions; it is not a scripting language. The runner rejects unknown action fields, action failures stop the current probe, and only the scenario step's `allow_failure` can make a failed probe non-fatal.
`allow_failure` must be a JSON boolean.

Current action catalog:

| Action type | Required fields | Optional fields | Outputs |
| --- | --- | --- | --- |
| `capture_command` | `argv` | `destination`, `kind`, `label` | none |
| `assert_namespaces_exist` | `namespaces` | none | none |
| `assert_ipv4_routes` | `namespace`, `expected_routes` | none | none |
| `assert_ipv6_routes` | `namespace`, `expected_routes` | none | none |
| `assert_igd_discovery` | `namespace` | `capture`, `label`, `output`, `timeout_s` | external IP in `output` (default `igd_external_ip`) and local IP in `<output>_local_ip` when available |
| `dhtnet_dsh_roundtrip` | `client_namespace`, `target_peer_id`, `bootstrap_host`, `bootstrap_port` | `capture`, `label`, `output`, `startup_delay_s`, `timeout_s`, `token` | echo token in `output` (default `roundtrip_token`) |
| `assert_upnp_mappings` | `router_namespace` | `target_namespace`, `capture`, `output`, `router_external_ip`, `session_capture`, `timeout_s` | mapped external ports in `output` (default `mapped_ports`) |

Add a new action type only for a new reusable assertion semantic. For diagnostics, prefer `capture_command`; for a new combination of existing checks, prefer a new `probes/*.json` definition.

Action modules are auto-loaded from `lib/probe_actions/`. To add one, create a
module with a `register_actions()` function and register each action with
`register_probe_action(...)`. The module name must not start with `_`.

```python
from lib.tools.probe_runner import ActionSchema, register_probe_action


def register_actions() -> None:
    register_probe_action(
        "my_new_action",
        ActionSchema(required=frozenset({"namespace"})),
        run_my_new_action,
    )
```

## Step input bindings

Scenario steps bind `inputs` into a probe. Common forms are:

```json
{ "role": "node" }
{ "role": "node", "field": "namespace" }
{ "service": "listener", "field": "peer_id" }
{ "fixture": "local-bootstrap", "field": "bootstrap_host" }
{ "context": "RUN_DIR" }
```

You can also pass literal values directly, for example:

```json
["ip", "route", "show"]
```

Steps run in order, so later steps can bind outputs from earlier steps.

DHTNet roundtrip probes use target-oriented inputs such as `target_namespace`
and `target_peer_id`. Bind those from whatever produced the endpoint identity
for the scenario, commonly a managed service, without making the probe depend
on the service runtime itself.

## Case 1: add a test using only existing pieces

This is the common path.

1. Pick the closest existing scenario and copy its structure.
2. Create `scenarios/<name>.json`.
3. Reuse an existing topology, fixture set, service set, and probe names.
4. Bind step inputs using roles, services, fixtures, and literals.
5. Inspect it with `./run.py describe <name>`.
6. Run it with `sudo ./run.py run <name>`.
7. Review artifacts under `artifacts/<run-id>/`.

Minimal example:

```json
{
  "name": "single-router-route-smoke",
  "description": "Bring up the single-router lab and inspect routes from the LAN service namespace.",
  "topology": "single-router",
  "steps": [
    {
      "name": "inspect_lan_routes",
      "probe": "capture-namespace-command",
      "inputs": {
        "namespace": { "role": "lan_node" },
        "argv": ["ip", "route", "show"],
        "capture_destination": "lan-routes.txt",
        "capture_label": "LAN routes",
        "capture_kind": "state-dump"
      }
    }
  ]
}
```

Use this path when the test is only a new composition.

## Case 2: add a test using existing pieces plus one new reusable piece
