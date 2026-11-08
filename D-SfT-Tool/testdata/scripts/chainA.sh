#!/bin/sh
# chainA -> chainB -> chainC: 3-level script chain for stop-all testing.
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "chain A started"
exec "$DIR/chainB.sh"
