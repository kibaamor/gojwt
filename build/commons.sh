#!/bin/bash

LIGHTGREEN='\033[1;32m'
LIGHTRED='\033[1;31m'
NC='\033[0m' # No Color

# If string is provided, print the error and exit 1
exit_shell()
{
    if [ -n "$1" ]; then
        echo -e "${LIGHTRED}EXIT $1${NC}"
        exit 1
    else
        echo "EXIT"
        exit 0
    fi
}
