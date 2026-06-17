# Virtual networking test lab

This directory contains a **composition-based** privileged test harness for exercising dhtnet under controlled network topologies.

The runner is `run.py`. It composes:

- **topologies** from `topologies/*.json`
- **fixtures** from `fixtures/*.json`
- **actors** from actor kinds such as `dsh-listener`
- **probes** from `probes/*.json`
- **scenarios** from `scenarios/*.json`

Scenario bring-up now goes through `run.py` composition rather than dedicated `setup-*.sh` wrapper scripts.

## Runner commands

```bash
./run.py help
./run.py list
./run.py describe upnp-static
sudo ./run.py run upnp-static
```

## Composition model

### Topologies

Topology files define:

- defaults
- namespaces
- network operations
- semantic roles

Current role examples:

- `lan_actor`
- `edge_router`
- `wan_client`
- `node`
- `uplink_a_router`
- `uplink_b_router`
- `wifi_router`
- `mobile_router`

`run.py` resolves role namespaces into placeholders such as:

- `ROLE_LAN_ACTOR_NAMESPACE`
- `ROLE_NODE_NAMESPACE`
- `ROLE_WAN_CLIENT_NAMESPACE`

### Fixtures

Fixtures are reusable services layered onto a topology. Current built-in fixture kinds are:

- `local-bootstrap`
  - starts a local OpenDHT bootstrap node in a role namespace
- `miniupnpd`
  - starts a miniupnpd instance on a router role and optionally waits for discovery from a client role

Current fixture definitions:

- `local-bootstrap`
- `miniupnpd-edge-router`
- `miniupnpd-uplink-a`
- `miniupnpd-uplink-b`
- `miniupnpd-wifi-router`

### Actors

Actors are long-running managed workloads. Current actor kind:

- `dsh-listener`
  - launches the bundled `actors/launch-dsh-listener.sh`
  - writes structured actor output JSON
  - emits `peer_id`

### Probes

Probe definitions live in `probes/*.json`. Current probe names are:

- `namespace-command`
  - run an arbitrary command inside a role namespace
- `igd-discovery`
  - run `upnpc -s` inside a role namespace
- `dsh-roundtrip`
  - run a real WAN-side dhtnet session and verify UPnP mappings during the active session

Each scenario step now binds generic `inputs` to a probe definition instead of embedding probe-specific fields in the scenario schema.

## Scenario schema

Scenario files are JSON objects with these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Scenario name |
| `description` | yes | Human-readable summary |
| `topology` | yes | Topology name |
| `lab` | yes | Lab identifier used for reporting and temp-state allocation |
| `fixtures` | no | Ordered fixture names |
| `actors` | no | Ordered actor definitions |
| `steps` | yes | Ordered probe steps |
| `notes` | no | Summary notes |
| `fields` | no | Extra summary fields |

Actor objects currently use:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Actor identifier |
| `kind` | yes | Actor kind, currently `dsh-listener` |
| `role` | yes | Topology role where the actor runs |
| `wait_s` | no | Actor readiness wait timeout |
| `bootstrap_fixture` | no | Fixture whose outputs provide the bootstrap endpoint |
| `options` | no | Reserved actor-specific options |

Step objects currently use:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Assertion/capture step name |
| `probe` | yes | Probe name from `probes/*.json` |
| `inputs` | no | Probe input bindings and literals |
| `capture` | no | Capture filename override |
| `label` | no | Capture label |
| `kind` | no | Capture kind |
| `allow_failure` | no | Marks failure as non-fatal |
| `copy_outputs` | no | Additional artifact copies, commonly probe summaries copied into the main capture set |

Supported step input binding forms:

- `{ "role": "node" }`
  - resolves the role's default `namespace`
- `{ "role": "node", "field": "namespace" }`
- `{ "actor": "listener", "field": "peer_id" }`
- `{ "fixture": "local-bootstrap", "field": "bootstrap_host" }`
- `{ "context": "RUN_DIR" }`
- literal scalars/lists/objects for direct values such as command argv arrays

## Low-level helpers

These scripts remain useful for direct inspection and debugging:

- `actors/launch-dsh-listener.sh`
- `probes/probe-dht-from-wan.sh`

They are low-level helpers, not the primary orchestration contract. The probe helper writes its nested
result bundle through the same Python result recorder that `run.py` uses for scenario-level summaries.

## Result artifacts

Each run writes artifacts under:

```text
extras/virtual-networking/artifacts/<run-id>/
```

Notable files:

- `summary.json`
- `summary.txt`
- `events.jsonl`
- `captures/`
- `.meta/run-state.json`

The structured run state records:

- topology metadata
- resolved context
- fixture outputs
- actor outputs

The canonical result contract is documented in `docs/result-format.md`.

## Requirements

- root privileges or equivalent capabilities
- prebuilt dhtnet tools such as `dsh` and `dhtnet-crtmgr`
- `miniupnpd`
- `upnpc`
- Python `opendht` bindings for the bootstrap helper and actor identity handling

If your dhtnet build outputs are not under `<repo>/build`, set `DHTNET_BUILD_DIR=/path/to/build`. If you keep the binaries elsewhere, point directly at them with `DHTNET_DSH_BIN` and `DHTNET_CRTMGR_BIN`.

The harness does **not** build dhtnet for you. Build it first as described in `BUILD.md`.
