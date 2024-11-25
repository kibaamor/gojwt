#!/bin/bash

CUR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck disable=SC1091
source "${CUR_DIR}"/commons.sh

FILE=./bin/golangci-lint
if [ ! -f "$FILE" ]; then
    echo "golangci-lint not installed, will download and install..."
    echo "Downloading golangci-lint..."
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.62.2
fi

echo "Execute static code and code style analysis..."
./bin/golangci-lint run --timeout 3m --verbose

error=$?
if [ "$error" -ne "0" ]; then
    echo -e "${LIGHTRED}ERROR: Execute golangci-lint: ${error}${NC}"
    exit_shell=$error
else
    echo -e "${LIGHTGREEN}SUCCESS: Execute golangci-lint${NC}"
fi

exit_shell "${exit_shell}"
