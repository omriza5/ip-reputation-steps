#!/bin/bash

# Batch IP Reputation Checker - Example Runner
# This script demonstrates how to run the batch IP checker

export ABUSEIPDB_API_KEY="db624c41f015c4c8036fa8a086dfba678dc8bbcb5939af71e8089fb995444e4199823bc2336364ba"
export IP_ADDRESSES="118.25.6.39,8.8.8.8,invalid-ip,1.1.1.1,gfcgh"
export CONFIDENCE_THRESHOLD="50"

# Run the batch checker
PYTHONPATH=src python3 check_ip_batch/main.py