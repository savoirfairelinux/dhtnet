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
sudo ./run.py run --run-id ci-upnp-static-1 upnp-static
```

`--run-id` is limited to letters, digits, `.`, `_`, and `-`, and must start with a letter or digit. The runner rejects path-like run IDs before replacing an existing artifact directory.

## Composition model

### Topologies

Topology files define:

- defaults
- namespaces
- network operations
- semantic roles

At runtime, namespace defaults such as `LAN_NS` and `NODE_NS` are prefixed with the run ID, so concurrent CI jobs do not share or delete the same network namespaces. The original role names stay available through bindings such as `{ "role": "node" }`.
The top-level `namespaces` list drives namespace creation during setup and deletion during cleanup; topology `operations` only wire and configure those namespaces.

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
  - starts a miniupnpd instance on a router role and optionally waits for discovery of the expected external IP from a client role

Current fixture definitions:

- `local-bootstrap`
- `local-bootstrap-ipv6`
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

- `capture-namespace-command`
  - run an arbitrary command inside a role namespace
- `igd-discovery`
  - assert that `upnpc -s` discovers a valid IGD from a role namespace
- `assert-ipv4-routes`
  - capture and assert expected IPv4 route entries inside a role namespace
- `assert-ipv6-routes`
  - capture and assert expected IPv6 route entries inside a role namespace
- `dsh-roundtrip`
  - `probe_sequence` probe that runs a real WAN-side dhtnet session and verifies a session-correlated UPnP mapping during the active session; if the session candidate ports cannot be parsed, the probe fails instead of accepting any actor mapping
- `dsh-ipv6-roundtrip`
  - `probe_sequence` probe that runs a real WAN-side dhtnet session over an IPv6-only routed lab path

Each scenario step binds generic `inputs` to a probe definition. Probe actions are schema-checked: unknown action fields are rejected, and new behavior should be added as a small typed action only when it represents a new assertion semantic.

## Scenario schema

Scenario files are JSON objects with these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Scenario name |
| `description` | yes | Human-readable summary |
| `topology` | yes | Topology name |
| `fixtures` | no | Ordered fixture names |
| `actors` | no | Ordered actor definitions |
| `steps` | yes | Ordered probe steps |
| `notes` | no | Summary notes |

Actor objects currently use:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Actor identifier |
| `kind` | yes | Actor kind, currently `dsh-listener` |
| `role` | yes | Topology role where the actor runs |
| `wait_s` | no | Actor readiness wait timeout |
| `bootstrap_fixture` | no | Fixture whose outputs provide the bootstrap endpoint |

Step objects currently use:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Assertion/capture step name |
| `probe` | yes | Probe name from `probes/*.json` |
| `inputs` | no | Probe input bindings and literals |
| `allow_failure` | no | JSON boolean marking failure as non-fatal |

Probe action failures stop the probe. Use step-level `allow_failure` only when a failed probe should not fail the whole scenario.

Supported step input binding forms:

- `{ "role": "node" }`
  - resolves the role's default `namespace`
- `{ "role": "node", "field": "namespace" }`
- `{ "actor": "listener", "field": "peer_id" }`
- `{ "fixture": "local-bootstrap", "field": "bootstrap_host" }`
- `{ "context": "RUN_DIR" }`
- literal scalars/lists/objects for direct values such as command argv arrays

## Result artifacts

Each run writes artifacts under:

```text
extras/virtual-networking/artifacts/<run-id>/
```

Notable files:

- `summary.json`
- `summary.txt`
- `events.jsonl`
- `run-state.json`
- `captures/`

The structured run state records:

- topology metadata
- resolved context
- fixture outputs
- actor outputs
- probe outputs and result directories

The canonical result contract is documented in `docs/result-format.md`.

## Requirements

- root privileges or equivalent capabilities
- iproute2 tools such as `ip` and `ss`
- NAT/filtering tools used by the checked-in topologies and probes: `iptables` and `nft`
- prebuilt dhtnet tools such as `dsh` and `dhtnet-crtmgr`
- `miniupnpd`
- `upnpc`
- Python `opendht` bindings for the bootstrap helper and actor identity handling

If your dhtnet build outputs are not under `<repo>/build`, set `DHTNET_BUILD_DIR=/path/to/build`. If you keep the binaries elsewhere, point directly at them with `DHTNET_DSH_BIN` and `DHTNET_CRTMGR_BIN`.

The harness does **not** build dhtnet for you. Build it first as described in `BUILD.md`.
