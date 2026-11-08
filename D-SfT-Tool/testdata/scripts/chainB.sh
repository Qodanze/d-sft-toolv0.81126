#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "chain B (level 2)"
exec "$DIR/chainC.sh"
