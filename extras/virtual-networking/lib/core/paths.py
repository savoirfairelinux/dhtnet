from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LIB_DIR = ROOT / "lib"
SCENARIO_DIR = ROOT / "scenarios"
TOPOLOGY_DIR = ROOT / "topologies"
FIXTURE_DIR = ROOT / "fixtures"
PROBE_DIR = ROOT / "probes"
DEFAULT_ARTIFACT_ROOT = ROOT / "artifacts"
DEFAULT_STATE_ROOT = Path(os.environ.get("VNET_STATE_ROOT", "/tmp/dhtnet-virtual-networking"))
