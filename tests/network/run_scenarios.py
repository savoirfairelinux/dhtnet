#!/usr/bin/env python3
"""
DHTNet network environment test orchestrator.

Generates and runs connection test scenarios across different network
configurations using Docker Compose (for infrastructure) and Linux
network namespaces (for per-scenario peer isolation).

Requires: root privileges, Docker with Compose V2, IPv6-capable Docker daemon.
"""

import argparse
import itertools
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Scenario generation
# ---------------------------------------------------------------------------

STACKS = {
    "v4":   {"ipv4": True,  "ipv6": False},
    "v6":   {"ipv4": False, "ipv6": True},
    "dual": {"ipv4": True,  "ipv6": True},
}

ALICE_IPV4 = "172.30.0.20"
ALICE_IPV6 = "fd00:d00::20"
BOB_IPV4   = "172.30.0.30"
BOB_IPV6   = "fd00:d00::30"

GATEWAY_IPV4 = "172.30.0.1"
GATEWAY_IPV6 = "fd00:d00::1"

BOOTSTRAP_IPV4 = "172.30.0.10"
BOOTSTRAP_IPV6 = "fd00:d00::10"
BOOTSTRAP_PORT = "4222"

TURN_IPV4 = "172.30.0.11"
TURN_IPV6 = "fd00:d00::11"
TURN_PORT = "3478"
TURN_USER = "test"
TURN_PASS = "test"
TURN_REALM = "dhtnet"

SUBNET_PREFIX = "172.30.0"
SUBNET_V6_PREFIX = "fd00:d00::"
SUBNET_MASK_V4 = "24"
SUBNET_MASK_V6 = "64"

COMPOSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml")


def generate_scenarios():
    """Generate all 18 test scenarios from the Cartesian product."""
    scenarios = []
    for turn, (alice_label, bob_label) in itertools.product(
        [True, False], itertools.product(STACKS, STACKS)
    ):
        name = f"{'turn' if turn else 'noturn'}-{alice_label}-{bob_label}"
        scenarios.append({
            "name": name,
            "turn": turn,
            "alice": STACKS[alice_label],
            "bob":   STACKS[bob_label],
        })
    return scenarios


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture=False, timeout=None):
    """Run a shell command, optionally capturing output."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    kwargs = {"check": check, "timeout": timeout}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(cmd, **kwargs)


def run_output(cmd, timeout=30):
    """Run command and return stripped stdout."""
    r = run(cmd, capture=True, timeout=timeout)
    return r.stdout.decode().strip()


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def docker_compose(*args, capture=False):
    cmd = ["docker", "compose", "-f", COMPOSE_FILE] + list(args)
    return run(cmd, capture=capture)


def start_infrastructure():
    """Build and start the Docker Compose services."""
    print("Starting Docker Compose infrastructure...")
    docker_compose("up", "-d", "--build", "--wait")
    print("Infrastructure is up.")


def stop_infrastructure():
    """Tear down Docker Compose services."""
    print("Stopping Docker Compose infrastructure...")
    docker_compose("down", "-v", "--timeout", "10")
    print("Infrastructure stopped.")


def get_docker_bridge_name():
    """Find the Linux bridge interface name for the 'dhtnet' Docker network."""
    # The network is named 'network_dhtnet' when created by compose from tests/network/
    result = run_output(["docker", "network", "ls", "--format", "{{.Name}}"])
    network_name = None
    for line in result.splitlines():
        if "dhtnet" in line:
            network_name = line.strip()
            break
    if not network_name:
        raise RuntimeError("Could not find Docker network containing 'dhtnet'")

    inspect = run_output(["docker", "network", "inspect", network_name])
    data = json.loads(inspect)
    bridge_name = data[0]["Options"].get("com.docker.network.bridge.name")
    if not bridge_name:
        # Fallback: Docker usually names it br-<short_id>
        net_id = data[0]["Id"][:12]
        bridge_name = f"br-{net_id}"
    return bridge_name


# ---------------------------------------------------------------------------
# Network namespace helpers
# ---------------------------------------------------------------------------

def ns_exists(name):
    r = run(["ip", "netns", "list"], capture=True, check=False)
    return name in r.stdout.decode()


def create_namespace(ns_name, veth_ns, veth_br, bridge, ipv4_addr, ipv6_addr, stack):
    """
    Create a network namespace, veth pair, attach to bridge, and configure
    addresses according to the stack settings.
    """
    # Clean up if leftover from a previous failed run
    if ns_exists(ns_name):
        run(["ip", "netns", "del", ns_name], check=False)

    run(["ip", "netns", "add", ns_name])

    # Create veth pair
    run(["ip", "link", "add", veth_ns, "type", "veth", "peer", "name", veth_br])

    # Move one end into the namespace
    run(["ip", "link", "set", veth_ns, "netns", ns_name])

    # Attach the other end to the Docker bridge
    run(["ip", "link", "set", veth_br, "master", bridge])
    run(["ip", "link", "set", veth_br, "up"])

    # Bring up lo and the veth inside the namespace
    run(["ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", ns_name, "ip", "link", "set", veth_ns, "up"])

    if stack["ipv4"]:
        run(["ip", "netns", "exec", ns_name, "ip", "addr", "add",
             f"{ipv4_addr}/{SUBNET_MASK_V4}", "dev", veth_ns])
        run(["ip", "netns", "exec", ns_name, "ip", "route", "add",
             "default", "via", GATEWAY_IPV4])

    if stack["ipv6"]:
        run(["ip", "netns", "exec", ns_name, "ip", "-6", "addr", "add",
             f"{ipv6_addr}/{SUBNET_MASK_V6}", "dev", veth_ns])
        run(["ip", "netns", "exec", ns_name, "ip", "-6", "route", "add",
             "default", "via", GATEWAY_IPV6])
    else:
        # Disable IPv6 entirely
        run(["ip", "netns", "exec", ns_name,
             "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
            check=False)
        run(["ip", "netns", "exec", ns_name,
             "sysctl", "-w", f"net.ipv6.conf.{veth_ns}.disable_ipv6=1"],
            check=False)


def destroy_namespace(ns_name, veth_br):
    """Delete a namespace and its associated veth bridge end."""
    run(["ip", "netns", "del", ns_name], check=False)
    # Deleting the namespace auto-destroys the veth pair, but clean up
    # the bridge end just in case
    run(["ip", "link", "del", veth_br], check=False)


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def build_cli_args(mode, stack, bootstrap_ipv4, bootstrap_ipv6,
                   turn_ipv4, turn_ipv6, use_turn, peer_id=None, timeout=30):
    """Build the CLI arguments for test_connection."""
    args = ["--mode", mode]

    # Choose bootstrap address based on available IP stacks
    if stack["ipv4"]:
        args += ["--bootstrap", f"{bootstrap_ipv4}:{BOOTSTRAP_PORT}"]
    else:
        args += ["--bootstrap", f"[{bootstrap_ipv6}]:{BOOTSTRAP_PORT}"]

    if use_turn:
        if stack["ipv4"]:
            args += ["--turn", f"{turn_ipv4}:{TURN_PORT}"]
        else:
            args += ["--turn", f"[{turn_ipv6}]:{TURN_PORT}"]
        args += ["--turn-user", TURN_USER,
                 "--turn-pass", TURN_PASS,
                 "--turn-realm", TURN_REALM]

    if peer_id:
        args += ["--peer-id", peer_id]

    args += ["--timeout", str(timeout)]
    return args


def run_scenario(scenario, binary_path, bridge, timeout):
    """Execute a single test scenario. Returns (passed: bool, elapsed: float)."""
    name = scenario["name"]
    alice_stack = scenario["alice"]
    bob_stack = scenario["bob"]
    use_turn = scenario["turn"]

    print(f"  Running: {name} ...", end=" ", flush=True)
    t0 = time.time()

    server_proc = None
    client_proc = None

    try:
        # Create namespaces
        create_namespace("ns-alice", "veth-alice", "veth-alice-br", bridge,
                         ALICE_IPV4, ALICE_IPV6, alice_stack)
        create_namespace("ns-bob", "veth-bob", "veth-bob-br", bridge,
                         BOB_IPV4, BOB_IPV6, bob_stack)

        # Build server args
        server_args = build_cli_args(
            "server", alice_stack,
            BOOTSTRAP_IPV4, BOOTSTRAP_IPV6,
            TURN_IPV4, TURN_IPV6,
            use_turn, timeout=timeout)

        server_cmd = ["ip", "netns", "exec", "ns-alice", binary_path] + server_args
        server_proc = subprocess.Popen(
            server_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        # Wait for the server to print its device ID (first line of stdout)
        peer_id = None
        deadline = time.time() + 30  # 30s to get the device ID
        while time.time() < deadline:
            line = server_proc.stdout.readline()
            if line:
                peer_id = line.decode().strip()
                if peer_id:
                    break
            if server_proc.poll() is not None:
                break
            time.sleep(0.1)

        if not peer_id:
            stderr_out = ""
            if server_proc.poll() is not None:
                stderr_out = server_proc.stderr.read().decode()
            elapsed = time.time() - t0
            print(f"FAIL  {elapsed:.1f}s (server did not produce device ID)")
            if stderr_out:
                for line in stderr_out.splitlines()[-5:]:
                    print(f"    server stderr: {line}")
            return False, elapsed

        # Build client args
        client_args = build_cli_args(
            "client", bob_stack,
            BOOTSTRAP_IPV4, BOOTSTRAP_IPV6,
            TURN_IPV4, TURN_IPV6,
            use_turn, peer_id=peer_id, timeout=timeout)

        client_cmd = ["ip", "netns", "exec", "ns-bob", binary_path] + client_args
        client_proc = subprocess.Popen(
            client_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        # Wait for client to finish
        try:
            client_proc.wait(timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            client_proc.kill()
            client_proc.wait()

        elapsed = time.time() - t0
        passed = client_proc.returncode == 0

        status = "PASS" if passed else "FAIL"
        print(f"{status}  {elapsed:.1f}s")

        if not passed:
            # Print last few lines of stderr for debugging
            client_stderr = client_proc.stderr.read().decode()
            for line in client_stderr.splitlines()[-5:]:
                print(f"    client stderr: {line}")

        return passed, elapsed

    except Exception as e:
        elapsed = time.time() - t0
        print(f"ERROR {elapsed:.1f}s ({e})")
        return False, elapsed

    finally:
        # Kill server if still running
        if server_proc and server_proc.poll() is None:
            server_proc.kill()
            server_proc.wait()
        if client_proc and client_proc.poll() is None:
            client_proc.kill()
            client_proc.wait()

        # Tear down namespaces
        destroy_namespace("ns-alice", "veth-alice-br")
        destroy_namespace("ns-bob", "veth-bob-br")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DHTNet network scenario test runner")
    parser.add_argument("--build-dir", required=True,
                        help="Path to the CMake build directory containing test_connection")
    parser.add_argument("--filter", default=None,
                        help="Regex to filter scenario names")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Per-scenario timeout in seconds (default: 60)")
    args = parser.parse_args()

    # Verify we are root
    if os.geteuid() != 0:
        print("Error: this script must be run as root (for network namespace operations).",
              file=sys.stderr)
        sys.exit(1)

    # Locate the test binary
    binary_path = os.path.join(args.build_dir, "test_connection")
    if not os.path.isfile(binary_path):
        print(f"Error: test_connection binary not found at {binary_path}", file=sys.stderr)
        sys.exit(1)
    if not os.access(binary_path, os.X_OK):
        print(f"Error: {binary_path} is not executable", file=sys.stderr)
        sys.exit(1)

    # Verify prerequisites
    for tool in ["ip", "docker"]:
        if not shutil.which(tool):
            print(f"Error: required tool '{tool}' not found in PATH", file=sys.stderr)
            sys.exit(1)

    # Generate and filter scenarios
    scenarios = generate_scenarios()
    if args.filter:
        pattern = re.compile(args.filter)
        scenarios = [s for s in scenarios if pattern.search(s["name"])]

    if not scenarios:
        print("No scenarios match the filter.", file=sys.stderr)
        sys.exit(1)

    print(f"Will run {len(scenarios)} scenario(s):\n")
    for s in scenarios:
        print(f"  {s['name']}")
    print()

    # Start infrastructure
    start_infrastructure()

    try:
        # Get the Docker bridge name
        bridge = get_docker_bridge_name()
        print(f"Docker bridge interface: {bridge}\n")

        # Run scenarios
        results = []
        for scenario in scenarios:
            passed, elapsed = run_scenario(scenario, binary_path, bridge, args.timeout)
            results.append((scenario["name"], passed, elapsed))

        # Print summary
        print()
        print(f"{'Scenario':<30} {'Result':<8} {'Time':>6}")
        print("─" * 30 + " " + "─" * 8 + " " + "─" * 6)
        for name, passed, elapsed in results:
            status = "PASS" if passed else "FAIL"
            print(f"{name:<30} {status:<8} {elapsed:>5.1f}s")

        n_pass = sum(1 for _, p, _ in results if p)
        n_total = len(results)
        print()
        print(f"Passed: {n_pass}/{n_total}")
        print(f"Failed: {n_total - n_pass}/{n_total}")

        # Exit with failure if any scenario failed
        sys.exit(0 if n_pass == n_total else 1)

    finally:
        stop_infrastructure()


if __name__ == "__main__":
    main()
