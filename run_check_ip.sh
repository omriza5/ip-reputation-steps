#!/bin/bash

# Single IP Reputation Checker - Example Runner
# This script demonstrates how to run the single IP checker

export ABUSEIPDB_API_KEY="db624c41f015c4c8036fa8a086dfba678dc8bbcb5939af71e8089fb995444e4199823bc2336364ba"
export IP_ADDRESS="118.25.6.39"
export CONFIDENCE_THRESHOLD="70"

# Run the checker
PYTHONPATH=src python3 check_ip/main.py