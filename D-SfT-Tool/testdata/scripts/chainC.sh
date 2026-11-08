#!/bin/sh
echo "chain C (level 3) - sleeping with a background child"
sleep 300 &
wait
