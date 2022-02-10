#!/bin/bash

RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'

FAILED="testfail"
OKAY="testokay"
API_FAIL="apifail"

echo -e "${ORANGE}Fail tests:${NC} $LINE"
while read -r LINE; do
    echo -e "${BLUE}Testing:${NC} $LINE"
    read -r EXPECTED

    # run the server on some port
    RESULT=$($LINE 2>&1 >/dev/null &)

    if [ "$RESULT" != "$EXPECTED" ]; then
        echo -e "${RED}Failed${NC}"
    fi
done < $FAILED

echo -e "${ORANGE}Normal tests:${NC} $LINE"

#kill all running servers
PID=$(ps | grep hinfosvc | awk -F' ' '{print $1}')
kill $PID

#run server on port 8080
./hinfosvc 8080 &

while read -r LINE; do
    echo -e "${BLUE}Testing:${NC} $LINE"

    RESULT=$($LINE) > /dev/null
    read -r EXPECTED

    if [ "$RESULT" != "$EXPECTED" ]; then
        echo -e "${RED}Failed${NC}"
    fi
done < $OKAY