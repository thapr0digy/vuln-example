#!/usr/bin/env python3
import json
import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Basic usage: ./opengrep_parse.py <base results filename> <pr results filename>
BASE_FILENAME = sys.argv[1]
PR_FILENAME = sys.argv[2]

try:
    with open(BASE_FILENAME, "r") as f:
        base_json = json.load(f)
except Exception as e:
    logger.error(f"Failed to retrieve base findings: {e}")
    sys.exit(1)

try:
    with open(PR_FILENAME, "r") as f:
        pr_json = json.load(f)
except Exception as e:
    logger.error(f"Failed to retrieve pr findings: {e}")
    sys.exit(1)

# Now we need to parse them and see what's different
base_runs = base_json["runs"]
pr_runs = pr_json["runs"]

base_set = set()
findings = list()

for run in base_runs:
    # Iterate through the results, capture the fingerprint id and add to set
    for result in run["results"]:
        base_set.add(result["fingerprints"]["matchBasedId/v1"])

for run in pr_runs:
    # Iterate through the results, capture the fingerprint id and add to set
    for result in run["results"]:
        if result["fingerprints"]["matchBasedId/v1"] not in base_set:
            # Add metadata for printing in the PR
            snippets = [
                location["region"]["snippet"]["text"]
                for location in result["locations"]
            ]
            findings.append({"snippets": snippets, "rule": result["ruleId"]})

print(f"Findings: {findings}")
