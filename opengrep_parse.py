import json
import argparse
import sys
import os

try:
    # Use the correct import based on the library's API
    from tree_sitter_language_pack import get_parser
except ImportError:
    print(
        "Error: 'tree-sitter-language-pack' not found. Please install it with: pip install tree-sitter tree-sitter-language-pack",
        file=sys.stderr,
    )
    sys.exit(1)


def get_function_context_with_tree_sitter(file_path, line_number):
    """
    Parses a source file using tree-sitter to find the enclosing function
    of a given line number. This is language-aware and highly accurate.

    Args:
        file_path (str): The path to the source file.
        line_number (int): The line number of the finding (1-indexed).

    Returns:
        str: The source code of the enclosing function, or None if not found.
    """
    try:
        # Determine the language from the file extension
        extension = os.path.splitext(file_path)[1]
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "c_sharp",
            ".rb": "ruby",
            ".rs": "rust",
        }
        lang_name = lang_map.get(extension)
        if not lang_name:
            return None  # Unsupported language

        # Use the correct get_parser function
        print(f"Parsing for language: {lang_name}")
        parser = get_parser(lang_name)
        if not parser:
            return None

        with open(file_path, "rb") as f:  # Read as bytes for tree-sitter
            source_bytes = f.read()

        tree = parser.parse(source_bytes)
        root_node = tree.root_node

        # Define what we consider a "function" node for different languages
        function_node_types = [
            "function_definition",
            "function_declaration",
            "method_definition",
            "arrow_function",
            "function_item",
            "method_declaration",
        ]

        # Traverse the tree to find the smallest enclosing function node
        smallest_enclosing_node = None

        def find_node(node):
            # Check if the current node's range contains the line number
            if (
                node.start_point[0] <= line_number - 1
                and node.end_point[0] >= line_number - 1
            ):
                print("Inside the if")
                if node.type in function_node_types:
                    smallest_enclosing_node = node
                    return
            # Recurse into children to find a more specific (smaller) node
            for child in node.children:
                print(f"Searching through new child: {child}")
                find_node(child)

        find_node(root_node)

        if smallest_enclosing_node:
            # Return the raw text of the function node
            print(f"Found smallest node: {smallest_enclosing_node}")
            return smallest_enclosing_node.text.decode("utf8").strip()

    except Exception:
        # Catch any errors during parsing (file not found, unsupported lang, etc.)
        return None
    return None


def get_function_context(result):
    """
    Tries to find the enclosing function's context from the SARIF result.

    It first checks 'codeFlows' (from taint-tracking). If unavailable, it falls
    back to parsing the source file with tree-sitter.

    Args:
        result (dict): A 'result' object from a SARIF file.

    Returns:
        str: A string representing the function context, or None if not found.
    """
    # 1. Try to get context from taint-tracking codeFlows (most reliable)
    try:
        code_flow = result.get("codeFlows", [{}])[0]
        thread_flow = code_flow.get("threadFlows", [{}])[0]
        function_location = thread_flow["locations"][0]["location"]["physicalLocation"]
        function_snippet = (
            function_location.get("region", {}).get("snippet", {}).get("text")
        )
        if function_snippet:
            return function_snippet.strip()
    except (KeyError, IndexError):
        print("Missing key...performing fallback method")
        pass  # Fallback to tree-sitter method

    # 2. Fallback: Parse the source file from the filesystem with tree-sitter
    try:
        physical_location = result["locations"][0]["physicalLocation"]
        file_path = physical_location["artifactLocation"]["uri"]
        line_number = physical_location["region"]["startLine"]
        return get_function_context_with_tree_sitter(file_path, line_number)
    except (KeyError, IndexError):
        return None

    return None


def create_finding_signature(result):
    """
    Creates a unique, hashable signature for a single Semgrep finding.

    The signature is based on the rule, file, the vulnerable code snippet,
    and the broader function context. This makes the signature highly resilient
    to line number changes while being specific enough to differentiate issues.
    """
    try:
        rule_id = result.get("ruleId")

        physical_location = result["locations"][0]["physicalLocation"]
        file_path = physical_location["artifactLocation"]["uri"]

        vulnerable_snippet = (
            physical_location.get("region", {}).get("snippet", {}).get("text")
        )
        if vulnerable_snippet:
            vulnerable_snippet = vulnerable_snippet.strip()

        function_context = get_function_context(result)
        context_key = function_context if function_context else vulnerable_snippet

        if not all([rule_id, file_path, context_key, vulnerable_snippet]):
            return None

        return (rule_id, file_path, context_key, vulnerable_snippet)
    except (KeyError, IndexError):
        return None


def parse_sarif_file(sarif_path):
    """
    Parses a SARIF file and extracts all findings, returning them as a set
    of unique signatures and a dictionary mapping signatures to full result objects.
    """
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: SARIF file not found at {sarif_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(
            f"Error: Could not decode JSON from {sarif_path}. Is the file valid?",
            file=sys.stderr,
        )
        sys.exit(1)

    findings = set()
    results_map = {}

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            signature = create_finding_signature(result)
            if signature and signature not in results_map:
                findings.add(signature)
                results_map[signature] = result

    return findings, results_map


def main():
    """
    s    Main function to compare two SARIF files and identify new findings.
    """
    parser = argparse.ArgumentParser(
        description="Compare two Semgrep SARIF files to find new vulnerabilities."
    )
    parser.add_argument(
        "base_sarif", help="Path to the SARIF file from the base branch (e.g., main)."
    )
    parser.add_argument(
        "head_sarif",
        help="Path to the SARIF file from the head branch (e.g., the PR branch).",
    )
    args = parser.parse_args()

    print(f"--- Loading base findings from: {args.base_sarif} ---")
    base_findings, _ = parse_sarif_file(args.base_sarif)
    print(f"Found {len(base_findings)} unique findings in the base scan.")

    print(f"\n--- Loading head findings from: {args.head_sarif} ---")
    head_findings, head_results_map = parse_sarif_file(args.head_sarif)
    print(f"Found {len(head_findings)} unique findings in the head scan.")

    new_finding_signatures = head_findings - base_findings

    print("\n--- Differential Scan Results ---")
    if not new_finding_signatures:
        print("✅ No new findings introduced in this pull request.")
        sys.exit(0)

    print(f"🚨 Found {len(new_finding_signatures)} new findings:")
    for i, signature in enumerate(new_finding_signatures, 1):
        result = head_results_map[signature]
        rule_id = result.get("ruleId")
        message = result["message"]["text"]
        location = result["locations"][0]["physicalLocation"]
        file_path = location["artifactLocation"]["uri"]
        line = location["region"]["startLine"]
        snippet = (
            location.get("region", {}).get("snippet", {}).get("text", "N/A").strip()
        )

        print("\n" + "=" * 40)
        print(f"Finding #{i}")
        print(f"  Rule:      {rule_id}")
        print(f"  File:      {file_path}:{line}")
        print(f"  Message:   {message}")
        print(f"  Snippet:   `{snippet}`")
        print("=" * 40)

    sys.exit(1)


if __name__ == "__main__":
    main()
