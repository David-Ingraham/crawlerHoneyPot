#!/bin/bash

LOGFILE="localTesting/logs/access.log"

echo "======================"
echo "  IP Access Counts"
echo "======================"

awk '{print $1}' "$LOGFILE" | sort | uniq -c | sort -nr | while read count ip; do
    printf "%-15s -> %5d hits\n" "$ip" "$count"
done

TOTAL_UNIQUE=$(awk '{print $1}' "$LOGFILE" | sort | uniq | wc -l)
TOTAL_ENTRIES=$(wc -l < "$LOGFILE")

echo "----------------------"
echo "Total unique IPs : $TOTAL_UNIQUE"
echo "Total log entries: $TOTAL_ENTRIES"
echo "======================"

