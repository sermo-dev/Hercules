#!/bin/sh
# Regression check for the ticket 030 Documents -> Application Support/Chain
# migration (StoragePaths.migrate). Runs on macOS against a scratch dir.
#   ./HerculesApp/Tools/MigrationScenarios/run.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
swiftc -O "$HERE/../../HerculesApp/StoragePaths.swift" "$HERE/main.swift" -o "$TMP/migtest"
"$TMP/migtest" "$TMP/run"
