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
- actor:
  - `listener` (`dsh-listener` in role `lan_actor`)
- probes:
  - `igd-discovery`
  - `dsh-roundtrip`

## What the baseline scenario does

1. Deletes any stale namespaces from the topology.
2. Applies the `single-router` topology.
3. Starts a local OpenDHT bootstrap node in the `wan_client` role.
4. Starts miniupnpd on the `edge_router` role.
5. Launches a real dhtnet `dsh` listener in the `lan_actor` role.
6. Confirms IGD discovery from the LAN side.
7. Starts a WAN-side `dsh` client, performs a real roundtrip, and checks that UPnP mappings exist while the session is active.
8. Stops fixtures and actors, then tears the topology down.

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
  captures/
  probes/
  .meta/run-state.json
```

Useful captures for `upnp-static` include:

- `captures/lan-upnpc.txt`
- `captures/probe-dht-from-wan.txt`
- `captures/probe-summary.txt`
- `probes/probe_dhtnet_from_wan/summary.txt`
- `captures/actors/listener.log`
- `captures/actors/listener-output.json`
- `captures/fixtures/miniupnpd-edge-router/logfile.log`
- `captures/fixtures/local-bootstrap/logfile.log`
