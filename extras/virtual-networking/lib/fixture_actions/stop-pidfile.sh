#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/shell/fixtures.sh"

vnet_fixture_stop_pidfile "${VNET_FIXTURE_PIDFILE:?missing VNET_FIXTURE_PIDFILE}"
