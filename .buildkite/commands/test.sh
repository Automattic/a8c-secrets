#!/bin/bash

set -euo pipefail

[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

echo "~~~ Checking Release..."
make check-release

echo "~~~ Running Tests..."
make test

# TODO: Re-enable once the first GitHub release has been created.
# The install script fetches from GitHub releases, which don't exist yet.
# echo "~~~ Testing \`install.sh\` script..."
# printf "a8c-secrets command: %s\n" "$(command -v a8c-secrets || echo "not found")"
# ./install.sh --prefix ./bin
# export PATH=$PATH:./bin
# a8c-secrets --version || echo "a8c-secrets not found"
