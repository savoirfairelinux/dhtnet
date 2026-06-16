#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_payload(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: actor output must be a JSON object")
    return payload


def command_long_id(args: argparse.Namespace) -> int:
    import opendht as dht

    cert = dht.Certificate(Path(args.certificate).read_bytes())
    print(cert.getLongId())
    return 0


def command_write(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "public_key_id": args.public_key_id,
        "peer_id": args.peer_id,
        "bootstrap_host": args.bootstrap_host,
        "certificate_path": args.certificate_path,
        "private_key_path": args.private_key_path,
    }
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return 0


def command_peer_id(args: argparse.Namespace) -> int:
    peer_id = read_payload(Path(args.input)).get("peer_id", "")
    if not isinstance(peer_id, str) or not peer_id:
        return 1
    print(peer_id)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Helpers for dhtnet actor metadata")
    subparsers = parser.add_subparsers(dest="command", required=True)

    long_id = subparsers.add_parser("long-id", help="Read a certificate long device ID")
    long_id.add_argument("certificate")
    long_id.set_defaults(func=command_long_id)

    write = subparsers.add_parser("write", help="Write actor output JSON")
    write.add_argument("output")
    write.add_argument("public_key_id")
    write.add_argument("peer_id")
    write.add_argument("bootstrap_host")
    write.add_argument("certificate_path")
    write.add_argument("private_key_path")
    write.set_defaults(func=command_write)

    peer_id = subparsers.add_parser("peer-id", help="Read peer_id from actor output JSON")
    peer_id.add_argument("input")
    peer_id.set_defaults(func=command_peer_id)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
