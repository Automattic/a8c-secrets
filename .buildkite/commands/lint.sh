#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Format check..."
make fmt-check

echo "~~~ Linting..."
make lint-pedantic
