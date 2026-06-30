# UPnP / dhtnet virtual lab flow

The preferred way to exercise the baseline isolated UPnP lab is the **composition runner**:

```bash
./run.py help
./run.py describe upnp-static
sudo ./run.py run upnp-static
```

That scenario composes:

- topology: `single-router`
- fixtures:
  - `local-bootstrap`
  - `miniupnpd-edge-router`
- service:
  - `listener` (`command` service in role `lan_node`)
- probes:
  - `igd-discovery`
  - `dsh-roundtrip`

## What the baseline scenario does

1. Deletes any stale namespaces from the topology.
2. Applies the `single-router` topology.
3. Starts a local OpenDHT bootstrap node in the `wan_client` role.
4. Starts miniupnpd on the `edge_router` role.
5. Launches a real dhtnet `dsh` listener service in the `lan_node` role.
6. Confirms IGD discovery from the LAN side.
7. Starts a WAN-side `dsh` client, performs a real roundtrip, and checks that UPnP mappings exist while the session is active.
8. Stops fixtures and services, then tears the topology down.

## Inspecting the scenario before running it

```bash
./run.py describe upnp-static
```

The supported workflow goes through `run.py`; the old `setup-*.sh` wrappers are no longer part of the documented flow.

## Artifacts to inspect after a run

```text
artifacts/<run-id>/
  summary.json
  summary.txt
  events.jsonl
  run-state.json
  captures/
```

Useful captures for `upnp-static` include:

- `captures/probes/discover_igd_from_lan/upnpc.txt`
- `captures/probes/probe_dhtnet_from_wan/wan-dsh-client.txt`
- `captures/probes/probe_dhtnet_from_wan/mapped-ports.txt`
- `captures/services/listener.log`
- `captures/fixtures/miniupnpd-edge-router/logfile.log`
- `captures/fixtures/local-bootstrap/logfile.log`
