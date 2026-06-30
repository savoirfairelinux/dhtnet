#!/usr/bin/env python3
import argparse
import signal
import time

import opendht as dht


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local OpenDHT bootstrap node")
    parser.add_argument("--bind", required=True, help="IP address to bind")
    parser.add_argument("--port", type=int, default=4222, help="UDP port to bind")
    args = parser.parse_args()

    node = dht.DhtRunner()
    if ":" in args.bind:
        node.run(ipv4="", ipv6=args.bind, port=args.port, is_bootstrap=True)
        endpoint = f"[{args.bind}]:{args.port}"
    else:
        node.run(ipv4=args.bind, ipv6="", port=args.port, is_bootstrap=True)
        endpoint = f"{args.bind}:{args.port}"
    print(f"BOOTSTRAP_READY {endpoint}", flush=True)

    running = True

    def handle_signal(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        while running:
            time.sleep(1)
    finally:
        node.shutdown()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
