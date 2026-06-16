# Virtual networking test lab

This directory contains privileged integration helpers for exercising dhtnet tools and library behavior under controlled networking conditions.

The current entry points are:

- `setup-fake-upnp-network.sh`
  - single LAN behind a NAT/IGD router plus a WAN peer namespace
- `setup-dual-router-handover-network.sh`
  - one node with two simultaneous Wi-Fi-like uplinks, each behind its own NAT/IGD and public IP
- `setup-dual-access-network.sh`
  - one node with a preferred Wi-Fi-like uplink plus a standby mobile-like uplink; only the Wi-Fi router exposes UPnP
- `run.py`
  - scenario runner that reuses the same topology definitions and result_summary contract
- `actors/launch-dsh-listener.sh`
  - launches a real dhtnet listener (`dsh`) with a temporary identity for the baseline WAN reachability scenario

The internal shell plumbing is now split into reusable libraries under `lib/`, and reusable JSON topology definitions live under `topologies/`.

## Current scripts

- `setup-fake-upnp-network.sh`
  - creates or tears down the static UPnP lab
- `setup-dual-router-handover-network.sh`
  - creates a dual-router topology suitable for Wi-Fi to Wi-Fi handover tests
- `setup-dual-access-network.sh`
  - creates a dual-access topology suitable for Wi-Fi to mobile-style path changes
- `probes/probe-dht-from-wan.sh`
  - establishes a real WAN-side dhtnet session and checks that UPnP mappings appear while that session is active
- `probes/dht-bootstrap-node.py`
  - minimal local OpenDHT bootstrap node used by the isolated virtual lab
- `run.py`
  - lists, describes, and runs scenario definitions from `scenarios/*.json`
- `actors/launch-dsh-listener.sh`
  - generates a throwaway dhtnet identity, expects prebuilt `dsh` / `dhtnet-crtmgr` binaries, and launches `dsh -l -a`

## Shell libraries

- `lib/common.sh`
  - shared helpers for dependency checks, state files, timestamps, and process cleanup
- `lib/netns.sh`
  - namespace existence and lifecycle helpers
- `lib/topology.sh`
  - reusable veth, route, and NAT primitives plus the JSON topology loader/applier used by multiple network layouts
- `lib/upnp.sh`
  - `miniupnpd` configuration and readiness helpers
- `lib/result-recording.sh`
  - shell-facing result recording helpers that manage run directories, captures, and intermediate JSONL records before rendering:
    - `summary.json`
    - `summary.txt`
    - `events.jsonl`
    - `captures/`
- `lib/result_summary.py`
  - Python summary builder / CLI used by both `lib/result-recording.sh` and `run.py`

## Topology definitions

- `topologies/single-router.json`
  - reusable definition for the current baseline LAN/router/WAN layout
- `topologies/dual-router-handover.json`
  - reusable definition for a node with two routed uplinks and two distinct IGDs
- `topologies/dual-access.json`
  - reusable definition for a preferred Wi-Fi-like uplink plus a standby mobile-like uplink

## Scenario definitions

- `scenarios/upnp-static.json`
  - baseline orchestrated scenario: setup, local bootstrap startup, managed dhtnet actor launch, IGD discovery, WAN dhtnet roundtrip + UPnP probe, teardown
- `scenarios/dual-router-handover-smoke.json`
  - topology smoke scenario for the dual-router handover lab
- `scenarios/dual-access-smoke.json`
  - topology smoke scenario for the dual-access lab

The setup wrappers now also support `--no-hold`, which creates the topology and exits without waiting. This is what the orchestrator uses so it can continue with probes and captures before calling the matching `down` action.

Scenarios can also manage a process inside their actor namespace by declaring an `actor_command`.

While a scenario runs, `run.py` prints concise major-step progress updates so you can see where execution is currently blocked without waiting for the final summary.

When a scenario declares `actor_command`:

- the command is started after topology setup and state discovery
- it runs inside the scenario actor namespace
- it runs as the original invoking user (`SUDO_USER` when present), not as root's effective home/session
- the runner exports `VNET_ROOT`, `VNET_REPO_ROOT`, and `VNET_STATE_ROOT` for actor helpers, and preserves `DHTNET_BUILD_DIR`, `DHTNET_DNC_BIN`, `DHTNET_DSH_BIN`, `DHTNET_CRTMGR_BIN`, and `DHTNET_BOOTSTRAP` when they are set
- if `VNET_ACTOR_READY_FILE` is present, the helper must create it only after the real foreground actor is ready
- the runner forces `HOME`, `USER`, and `LOGNAME` to the target user's values and captures startup/output in:
  - `captures/actor.log`
  - `captures/actor-meta.txt`
- the command should keep the dhtnet actor in the foreground; if it exits during the launch wait window, the run is marked failed

`scenarios/upnp-static.json` now launches a bundled dhtnet `dsh` actor automatically and starts a local OpenDHT bootstrap node inside the virtual lab. The baseline invocation is:

```bash
sudo ./run.py run upnp-static
```

If your dhtnet build outputs are not under `<repo>/build`, set `DHTNET_BUILD_DIR=/path/to/build`. If you keep the binaries elsewhere, point directly at them with `DHTNET_DSH_BIN` and `DHTNET_CRTMGR_BIN`. The virtual-networking helpers do **not** build dhtnet for you; build it first as described in `BUILD.md`.

Before each scenario setup, the orchestrator also issues the scenario's `down` action as a best-effort pre-cleanup step so stale namespaces or state files do not cause immediate setup failures on repeated runs.

When the setup wrapper records topology-side paths such as `MINIUPNPD_LOGFILE`, `UPNPC_DISCOVERY_LOG`, or generated config files in the lab state file, the orchestrator copies those artifacts into the run captures before teardown so router-side evidence survives temp-directory cleanup.

## Result artifacts

Probe-oriented scripts can now emit reusable artifacts under:

```text
extras/virtual-networking/artifacts/<run-id>/
```

These artifacts are ignored by git and are intended to be inspected locally or harvested by future orchestration code.

The canonical summary contract is documented in `docs/result-format.md`.

The orchestrator writes the same artifact shape as the shell probe scripts, so runs remain comparable across manual scripts and future automated scenarios.

## Lab state

The setup script now persists exact lab state in:

```text
/tmp/dhtnet-virtual-networking/
```

This lets follow-up tools discover the active lab without hardcoding the router public IP or relying on broad temp-directory scans.

## Notes

- These helpers require root privileges or equivalent capabilities.
- They are not adapted for CI integration as of yet.
- The next planned work slice after this is dynamic scenario work on top of the orchestrator, starting with route changes and handover events.
