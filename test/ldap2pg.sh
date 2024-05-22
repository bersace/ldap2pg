#!/bin/bash
# dev wrapper for conftest
set -e
cd "$(dirname "$0")/.."
exec go run ./cmd/ldap2pg "$@"
