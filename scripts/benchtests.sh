#!/bin/bash

CUR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck disable=SC1091
source "${CUR_DIR}"/commons.sh

echo "Execute benchmark tests..."
# Execute all time and memory tests in files with tag `benchmark`, which name begins with `Benchmark`
(
    set -x
    env CGO_ENABLED=0 go test -bench Benchmark -benchmem -tags=benchmark ./...
)
error=$?
if [ "$error" -ne "0" ]; then
    echo -e "${LIGHTRED}ERROR: Execute benchmark tests: ${error}${NC}"
    exit_shell=$error
else
    echo -e "${LIGHTGREEN}SUCCESS: Execute benchmark tests${NC}"
fi

exit_shell "${exit_shell}"
