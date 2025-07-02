import json
import argparse
import sys

def create_finding_signature(result):
    """
    Creates a unique, hashable signature for a single Semgrep finding.

    The signature is a tuple containing the rule ID, the primary file path,
    and the finding's message text. This combination is robust enough to
    uniquely identify a specific vulnerability at a specific code location.

    Args:
        result (dict): A 'result' object from a SARIF file.

    Returns:
        tuple: A unique signature for the finding, or None if the result
               is malformed.
    """G
    try:
        rule_id = result.get('ruleId')
        message = result['message']['text']
        # We use the first location as the primary identifier for the finding's location
        location = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
        
        if not all([rule_id, message, location]):
            return None
            
        return (rule_id, location, message)
    except (KeyError, IndexError):
        # Handle cases where the result object doesn't have the expected structure
        return None

def parse_sarif_file(sarif_path):
    """
    Parses a SARIF file and extracts all findings, returning them as a set
    of unique signatures and a dictionary mapping signatures to full result objects.

    Args:
        sarif_path (str): The file path to the SARIF file.

    Returns:
        tuple: A tuple containing:
            - set: A set of unique finding signatures.
            - dict: A dictionary mapping each signature to its full result object.
    """
    try:
        with open(sarif_path, 'r') as f:
            sarif_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: SARIF file not found at {sarif_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {sarif_path}. Is the file valid?", file=sys.stderr)
        sys.exit(1)

    findings = set()
    results_map = {}
    
    # SARIF files can have multiple 'runs', so we iterate through them
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            signature = create_finding_signature(result)
            if signature:
                findings.add(signature)
                results_map[signature] = result
                
    return findings, results_map

def main():
    """
    Main function to compare two SARIF files and identify new findings.
    """
    parser = argparse.ArgumentParser(
        description="Compare two Semgrep SARIF files to find new vulnerabilities."
    )
    parser.add_argument(
        "base_sarif", 
        help="Path to the SARIF file from the base branch (e.g., main)."
    )
    parser.add_argument(
        "head_sarif", 
        help="Path to the SARIF file from the head branch (e.g., the PR branch)."
    )
    args = parser.parse_args()

    print(f"--- Loading base findings from: {args.base_sarif} ---")
    base_findings, _ = parse_sarif_file(args.base_sarif)
    print(f"Found {len(base_findings)} unique findings in the base scan.")

    print(f"\n--- Loading head findings from: {args.head_sarif} ---")
    head_findings, head_results_map = parse_sarif_file(args.head_sarif)
    print(f"Found {len(head_findings)} unique findings in the head scan.")

    # Perform the diff to find new vulnerabilities
    new_finding_signatures = head_findings - base_findings

    print("\n--- Differential Scan Results ---")
    if not new_finding_signatures:
        print("✅ No new findings introduced in this pull request.")
        sys.exit(0)

    print(f"🚨 Found {len(new_finding_signatures)} new findings:")
    for i, signature in enumerate(new_finding_signatures, 1):
        result = head_results_map[signature]
        rule_id = result.get('ruleId')
        message = result['message']['text']
        location = result['locations'][0]['physicalLocation']
        file_path = location['artifactLocation']['uri']
        line = location['region']['startLine']

        print("\n" + "="*40)
        print(f"Finding #{i}")
        print(f"  Rule:      {rule_id}")
        print(f"  File:      {file_path}")
        print(f"  Line:      {line}")
        print(f"  Message:   {message}")
        print("="*40)
    
    # Exit with a non-zero status code to indicate that new issues were found,
    # which can be used to fail a CI/CD pipeline.
    sys.exit(1)

if __name__ == "__main__":
    main()

