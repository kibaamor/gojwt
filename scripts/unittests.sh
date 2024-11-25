#!/bin/bash

CUR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck disable=SC1091
source "${CUR_DIR}"/commons.sh

# $1: Enable verbose mode
VERBOSE="$1"
if [ -n "$VERBOSE" ]; then
    VERBOSE="-v"
fi

echo "Execute unit tests..."
(
    set -x
    env CGO_ENABLED=0 go test "${VERBOSE}" -coverprofile=test/reports/coverage_unit.out -tags=unit ./...
)
error=$?
if [ "$error" -ne "0" ]; then
    echo -e "${LIGHTRED}ERROR: Execute unit tests: ${error}${NC}"
    exit_shell=$error
else
    echo -e "${LIGHTGREEN}SUCCESS: Execute unit tests${NC}"
fi

echo "Generate coverage report..."
(
    set -x
    go tool cover -html=test/reports/coverage_unit.out -o test/reports/coverage_unit.html
)
error=$?
if [ "$error" -ne "0" ]; then
    echo -e "${LIGHTRED}ERROR: Generate coverage report: ${error}${NC}"
fi

exit_shell "${exit_shell}"
