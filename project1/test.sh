#!/bin/bash

RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'

FAILED="testfail"

while read -r LINE; do
    echo -e "${BLUE}Testing:${NC} $LINE"
    read -r EXPECTED

    # run the server on some port
    RESULT=$($LINE 2>&1 >/dev/null &)

    if [ "$RESULT" != "$EXPECTED" ]; then
        echo -e "${RED}Failed${NC}"
    fi
done < $FAILED
