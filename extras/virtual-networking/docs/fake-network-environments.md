# UPnP/DHTNet Testing with Virtual Network Namespaces

## Overview

These test procedures verify that **dhtnet** correctly uses UPnP in a
controlled virtual network. The lab is set up with `setup-fake-upnp-network.sh`,
which creates three network namespaces:

```text
 ┌───────────────┐      ┌──────────────────────┐      ┌──────────────┐
 │  lan (dhtnet) │──────│  rtr (NAT+miniupnpd) │──────│  wan (peer)  │
 │ 192.168.100.2 │      │  .100.1 ←→ 11.0.0.2  │      │   11.0.0.1   │
 └───────────────┘      └──────────────────────┘      └──────────────┘
```

A dhtnet actor runs in `lan` behind NAT. The `wan` namespace simulates an external peer and also hosts a local OpenDHT bootstrap node for the isolated lab.
miniupnpd on `rtr` provides the UPnP IGD that the dhtnet actor discovers during real peer setup.

### Prerequisites

- Root access (netns operations require it)
- A built dhtnet tree with `BUILD_TOOLS=ON`, providing `dsh` and `dhtnet-crtmgr` (see `BUILD.md`)
- `miniupnpd` installed (`sudo apt install miniupnpd` on Debian)
- `upnpc` (miniupnpc client) installed
- `opendht` Python package (`pip install opendht`) — for test case 3 only

### Starting the lab

All commands below assume your working directory is the directory containing
the scripts.

```bash
# Terminal 1: start the network lab (stays in foreground; Ctrl-C to stop)
sudo ./setup-fake-upnp-network.sh

# Terminal 2: open a shell in the lan namespace as your user
sudo ip netns exec lan sudo -u $USER -H \
  env VNET_ROOT="$PWD" VNET_REPO_ROOT="$(cd ../.. && pwd)" \
      VNET_STATE_ROOT="${VNET_STATE_ROOT:-/tmp/dhtnet-virtual-networking}" \
  bash -l

# In the lan shell, start a dhtnet listener
cd "$VNET_ROOT"
./actors/launch-dsh-listener.sh --bootstrap 11.0.0.1 > /tmp/dhtnet-actor.log 2>&1
```

### Key reference: dhtnet port ranges

| What                  | Range / Default                              |
|-----------------------|----------------------------------------------|
| UPnP UDP external     | 20000–25000 (hardcoded in `upnp_context.cpp`)|
| UPnP TCP external     | 10000–15000 (idem)                           |
| Default DHT port      | 0 (auto-select within range)                 |

### Key dhtnet log strings to watch for

Run the dhtnet actor with logging captured (the provided `actors/launch-dsh-listener.sh` does this). Relevant log patterns:

| Event                    | Log pattern (grep for)                          |
|--------------------------|-------------------------------------------------|
| IGD discovered           | `Discovered a new IGD`                          |
| IGD validated            | `Added a new IGD`                               |
| External IP obtained     | `Setting IGD.*public address`                   |
| Mapping requested        | `Request mapping DHTNET-`                       |
| Mapping created          | `successfully performed`                        |
| Mapping failed           | `Request for mapping.*failed`                   |
| DHT UPnP port allocated  | `Allocated port changed to`                     |
| DHT started on port      | `Mapping request is in.*state: starting the DHT`|

---

## Test Case 1: Session Setup — dhtnet Creates UPnP Mappings During a Real Peer Session

**Goal:** Confirm that when a WAN-side peer initiates a real dhtnet session, dhtnet
discovers the IGD and creates UPnP port mappings on the router.

### Steps

1. **Verify clean state** inside the `lan` namespace — no pre-existing mappings:

   ```bash
   upnpc -l
   ```

   Expected: no mappings listed (or only unrelated ones).

2. **Start the dhtnet actor** inside the `lan` namespace:

   ```bash
   # In the lan shell (Terminal 2):
   cd "$VNET_ROOT"
   ./actors/launch-dsh-listener.sh --bootstrap 11.0.0.1 > /tmp/dhtnet-actor.log 2>&1
   ```

3. **Trigger a real WAN-side dhtnet session** from the host:

   ```bash
   sudo bash probes/probe-dht-from-wan.sh --actor-log /tmp/dhtnet-actor.log
   ```

4. **Check the router's mapping table while that session is active:**

   ```bash
   upnpc -l
   ```

5. **Check the dhtnet actor logs** for UPnP activity:

   ```bash
   grep -iE "IGD|UPnP|mapping.*performed|public address" /tmp/dhtnet-actor.log
   ```

### PASS criteria

- `upnpc -l` shows **at least one UDP mapping** in the 20000–25000 range
  pointing to `192.168.100.2`.
- The dhtnet actor logs contain `Discovered a new IGD` and `successfully performed`.
- The WAN-side probe completes a real `dsh` roundtrip while the mapping is present.

### FAIL criteria

- No mappings appear during the active WAN-side session.
- Logs show `Request for mapping.*failed` with no subsequent success.
- `upnpc -l` reports one of the following scenarios:

   ```bash
   connect: Connection timed out
   No valid UPNP Internet Gateway Device found.
   ```

   or

   ```bash
   sendto: Network is unreachable
   No IGD UPnP Device found on the network !
   ```

   In these cases, check that the `setup-fake-upnp-network.sh` script is still running and that `upnpc -l` is called from inside the `lan` namespace.

---

## Test Case 2: WAN Reachability — Real dhtnet Access Through UPnP

**Goal:** Confirm that an external peer in the `wan` namespace can establish a
real dhtnet session through the router and that UPnP mappings appear while that session is active.

### Steps

1. **Start the dhtnet actor** in the lan namespace.

2. **Run the probe from the host** (not from inside any namespace):

   ```bash
   sudo bash probes/probe-dht-from-wan.sh --actor-log /tmp/dhtnet-actor.log
   ```

   The script extracts the actor peer ID from the actor log, starts a WAN-side
   `dsh` client against the local bootstrap node, verifies a real roundtrip over
   dhtnet, and then inspects the router UPnP mapping table while that session is active.

### PASS criteria

- The script completes a real WAN-side `dsh` roundtrip to the LAN actor.
- The script finds at least one UPnP-mapped UDP port while that session is active.

### FAIL criteria

- **No roundtrip:** The WAN-side `dsh` client never echoes the probe token back.
- **No mapped ports:** The dhtnet session completes without any UPnP mappings being present, which means the lab did not exercise the intended UPnP path.

---

## Tearing Down

```bash
sudo ./setup-fake-upnp-network.sh down
```
