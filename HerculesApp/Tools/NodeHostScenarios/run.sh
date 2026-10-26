#!/bin/sh
# Regression check for the ticket 028 wake/foreground coordination
# (NodeSessionState, OnceGate in WakeCoordination.swift). Runs on macOS.
#   ./HerculesApp/Tools/NodeHostScenarios/run.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
swiftc -O "$HERE/../../HerculesApp/WakeCoordination.swift" "$HERE/../../HerculesApp/NotificationHistory.swift" \
    "$HERE/main.swift" -o "$TMP/nodehosttest"
"$TMP/nodehosttest"
