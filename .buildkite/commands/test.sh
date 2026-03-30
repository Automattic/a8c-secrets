#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Checking Release..."
make check-release

echo "~~~ Running Tests..."
make test

echo "~~~ Testing \`install.sh\` script..."
printf "a8c-secrets on PATH before install: %s\n" "$(command -v a8c-secrets 2>/dev/null || echo "not found")"
./install.sh --prefix ./bin
export PATH="${PWD}/bin:${PATH}"
a8c-secrets --version
