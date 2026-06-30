# Adding tests to the virtual-networking harness

In this harness, a “test” is usually a **scenario** under `scenarios/*.json`. A scenario composes:

- a **topology** from `topologies/*.json`
- optional **fixtures** from `fixtures/*.json`
- optional long-running **actors** located in `actors/`
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
| Only a new combination of existing topology/fixtures/actors/probes | a new `scenarios/*.json` file |
| A new command/check that fits existing runtime behavior | a new `probes/*.json` file, and maybe a small typed action in `lib/tools/probe_actions.py` |
| A new router/bootstrap instance using an existing built-in fixture kind | a new `fixtures/*.json` file |
| A new network layout | a new `topologies/*.json` file |
| A new fixture kind, actor kind, or probe action type | Python/runtime changes in `lib/runtime/`, `lib/loaders/`, or `lib/tools/probe_actions.py` plus the new JSON definition(s) |

Prefer reusable pieces over one-off scenario-specific logic.

## Scenario building blocks

### Topologies

Topologies define the network shape, defaults, roles, namespaces, and operations.

Keep role names stable when they mean the same thing across labs, for example:

- `lan_actor`
- `edge_router`
- `wan_client`
- `node`

That lets probes bind to intent instead of hard-coded namespace names.
Roles are the topology's semantic API: they map reusable fixture, actor, and probe definitions onto the concrete namespaces in a specific lab.

The top-level `namespaces` list drives both setup namespace creation and cleanup. `operations` should only wire and configure those namespaces.

### Fixtures

Fixtures are reusable services layered onto a topology. Current built-in kinds are:

- `local-bootstrap`
- `miniupnpd`

If you only need a different instance of one of those kinds, add a new JSON file under `fixtures/`.
Fixture roles are declared through the options consumed by the fixture kind, such as `options.role` and optional discovery role fields.
For `miniupnpd`, discovery checks validate the expected external IP. The expected IP defaults to `options.ext_ip`; use `options.discovery_expected_external_ip` only when it differs, and use `options.discovery_bind_ip` for multi-uplink clients that must query a specific local address.

### Actors

Actors are long-running managed processes started by the runner. The current checked-in actor kind is:

- `dsh-listener`

Actors write structured outputs that later steps can consume.

### Probes

Probes are reusable step definitions in `probes/*.json`. Each probe carries an ordered `probe_sequence`
of typed actions implemented by `lib/tools/probe_actions.py`, so the
actual assertions and captures stay visible in the probe file instead of disappearing into a shell wrapper.

Probe JSON composes typed actions; it is not a scripting language. The runner rejects unknown action fields, action failures stop the current probe, and only the scenario step's `allow_failure` can make a failed probe non-fatal.
`allow_failure` must be a JSON boolean.

Current action catalog:

| Action type | Required fields | Optional fields | Outputs |
| --- | --- | --- | --- |
| `capture_command` | `argv` | `destination`, `kind`, `label` | none |
| `assert_namespaces_exist` | `namespaces` | none | none |
| `assert_ipv4_routes` | `namespace`, `expected_routes` | none | none |
| `assert_igd_discovery` | `namespace` | `capture`, `label`, `output`, `timeout_s` | external IP in `output` (default `igd_external_ip`) and local IP in `<output>_local_ip` when available |
| `dhtnet_dsh_roundtrip` | `client_namespace`, `peer_id`, `bootstrap_host`, `bootstrap_port` | `capture`, `label`, `output`, `startup_delay_s`, `timeout_s`, `token` | echo token in `output` (default `roundtrip_token`) |
| `assert_upnp_mappings` | `router_namespace` | `actor_namespace`, `capture`, `output`, `router_external_ip`, `session_capture`, `timeout_s` | mapped external ports in `output` (default `mapped_ports`) |

Add a new action type only for a new reusable assertion semantic. For diagnostics, prefer `capture_command`; for a new combination of existing checks, prefer a new `probes/*.json` definition.

## Step input bindings

Scenario steps bind `inputs` into a probe. Common forms are:

```json
{ "role": "node" }
{ "role": "node", "field": "namespace" }
{ "actor": "listener", "field": "peer_id" }
{ "fixture": "local-bootstrap", "field": "bootstrap_host" }
{ "context": "RUN_DIR" }
```

You can also pass literal values directly, for example:

```json
["ip", "route", "show"]
```

Steps run in order, so later steps can bind outputs from earlier steps.

## Case 1: add a test using only existing pieces

This is the common path.

1. Pick the closest existing scenario and copy its structure.
2. Create `scenarios/<name>.json`.
3. Reuse an existing topology, fixture set, actor set, and probe names.
4. Bind step inputs using roles, actors, fixtures, and literals.
5. Inspect it with `./run.py describe <name>`.
6. Run it with `sudo ./run.py run <name>`.
7. Review artifacts under `artifacts/<run-id>/`.

Minimal example:

```json
{
  "name": "single-router-route-smoke",
  "description": "Bring up the single-router lab and inspect routes from the LAN actor namespace.",
  "topology": "single-router",
  "steps": [
    {
      "name": "inspect_lan_routes",
      "probe": "capture-namespace-command",
      "inputs": {
        "namespace": { "role": "lan_actor" },
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

Usually the missing piece should be added as a reusable **probe**, **fixture definition**, or **topology**, then used from a scenario.

### Adding a new probe definition

Use this when you need a new check or command but the current runtime model is already enough.

1. Add `probes/<name>.json`.
2. Declare `required_inputs`.
3. Put the real captures and assertions in `probe_sequence`.
4. Prefer composing existing typed actions; add a small new action in `lib/tools/probe_actions.py` only when the probe needs a new assertion semantic.
5. Use the new probe from a scenario step.

Example:

```json
{
  "name": "ip-neigh-dump",
  "description": "Dump neighbor state from a resolved namespace.",
  "required_inputs": ["namespace", "capture_destination", "capture_label"],
  "probe_sequence": [
    {
      "id": "capture-neighbors",
      "type": "capture_command",
      "argv": ["ip", "netns", "exec", "{namespace}", "ip", "neigh", "show"],
      "destination": "{capture_destination}",
      "label": "{capture_label}",
      "kind": "state-dump"
    }
  ]
}
```

Then in a scenario:

```json
{
  "name": "inspect_neighbors",
  "probe": "ip-neigh-dump",
  "inputs": {
    "namespace": { "role": "node" },
    "capture_destination": "node-neigh.txt",
    "capture_label": "Node neighbors"
  }
}
```

### Adding a new fixture definition

Use this when the runner already supports the fixture **kind**, but you need a new instance or option set.

1. Add `fixtures/<name>.json`.
2. Reuse an existing kind such as `miniupnpd` or `local-bootstrap`.
3. Bind its `options` to topology placeholders.
4. Add the fixture name to the scenario’s `fixtures` list.
5. Consume its outputs from actor/bootstrap or probe inputs if needed.

### Adding a new topology

Use this when the existing labs do not model the network you need.

1. Add `topologies/<name>.json`.
2. Define `defaults`, `roles`, `namespaces`, and `operations`.
3. Prefer stable semantic role names so existing probes can bind to them.
4. Reuse existing fixtures and probes where possible.
5. Add a scenario on top of that topology.

## Case 3: add a test starting from scratch

Use this when the test needs a new lab shape and at least one new reusable runtime piece.

Recommended order:

1. Define the test intent in one sentence.
2. Add the **topology** first.
3. Add **fixture definitions** that the topology needs.
4. Add or reuse **actors**.
5. Add or reuse **probes**.
6. Create the **scenario**.

### When runtime code changes are required

JSON-only additions are enough for many tests, but these cases still require Python changes:

| If you add... | You will likely need to change... |
| --- | --- |
| a new fixture kind | `lib/runtime/fixture_runtime.py` |
| a new actor kind | `lib/runtime/actor_runtime.py` |
| a new probe action type | `lib/tools/probe_actions.py` and maybe `lib/tools/probe_runner.py` if the framework changes |
| new validation rules for scenario/probe schema | `lib/loaders/context_loader.py` |

You may also need a shell helper under:

- `actors/`
- `lib/`

But keep those helpers reusable and narrow in scope.

## Validation workflow

Use the smallest validation that covers your change.

### If you changed only JSON scenario/topology/fixture/probe definitions

```bash
./run.py describe <scenario-name>
sudo ./run.py run <scenario-name>
```

### If you changed Python runner code

```bash
./run.py describe <scenario-name>
sudo ./run.py run <scenario-name>
```

### If you changed shell helpers

```bash
./run.py describe <scenario-name>
sudo ./run.py run <scenario-name>
```

## What to review after a run

Look at:

- `artifacts/<run-id>/summary.txt`
- `artifacts/<run-id>/summary.json`
- `artifacts/<run-id>/captures/`
- `artifacts/<run-id>/captures/probes/`
- `artifacts/<run-id>/run-state.json`

`run-state.json` is especially useful when wiring fixtures, actors, and later probe steps together.

## Good defaults

- Start from the closest checked-in scenario instead of writing a test from zero.
- Prefer adding a new reusable probe definition over embedding custom logic in a scenario.
- Prefer stable role names across topologies.
- Keep scenario step names clear; they become assertion names and probe result directory names.

## Current reference examples

Use these as templates:

- `scenarios/upnp-static.json`
  - full composition: topology + fixtures + actor + probe chaining
- `scenarios/dual-access-smoke.json`
  - simple namespace inspection using existing probes
- `probes/dsh-roundtrip.json`
  - reusable probe definition with defaults and copied outputs
- `fixtures/miniupnpd-edge-router.json`
  - fixture definition reusing a built-in kind
- `topologies/single-router.json`
  - baseline topology with stable roles
