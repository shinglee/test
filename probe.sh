#!/bin/sh

echo "(T|A,B,C,D)"
echo "Target: $1"
echo "A: $2"
echo "B: $3"
echo "C: $4"
echo "D: $5"

sudo scamper -c "ping -P icmp-echo -T tsprespec=$2,$3,$4,$5" -i $1
