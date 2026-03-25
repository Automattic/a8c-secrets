#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Checking Release..."
make check-release

echo "~~~ Running Tests..."
make test

echo "~~~ Testing \`install.sh\` script..."
printf "a8c-secrets command: %s\n" "$(command -v a8c-secrets || echo "not found")"
./install.sh --prefix ./bin
export PATH=$PATH:./bin
a8c-secrets --version || echo "a8c-secrets not found"
