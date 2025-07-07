import json
import sys
import re
from git import Repo, Diff
from typing import Dict, List, Set, Tuple


def parse_git_diff_lines(diff_output: str) -> Dict[str, Set[int]]:
    """
    Parses git diff output to get changed lines per file.
    Only considers added/modified lines in hunks starting with '+'.
    """
    changed_lines_per_file = {}
    current_file = None

    # Regex to capture file path in diff header (a/path/to/file.py or b/path/to/file.py)
    file_header_re = re.compile(r"^\+\+\+ b/(.*)$")
    # Regex to capture hunk header @@ -old_start,old_count +new_start,new_count @@
    hunk_header_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+),(\d+)? @@")

    for line in diff_output.splitlines():
        file_match = file_header_re.match(line)
        if file_match:
            current_file = file_match.group(1)
            changed_lines_per_file[current_file] = set()
            continue

        if current_file and line.startswith("@@"):
            hunk_match = hunk_header_re.match(line)
            if hunk_match:
                start_line = int(hunk_match.group(1))
                line_count = (
                    int(hunk_match.group(2)) if hunk_match.group(2) else 1
                )  # Default to 1 if no count
                current_line_in_hunk = start_line
                continue  # Move to next line after hunk header

        if current_file and current_line_in_hunk is not None:
            if line.startswith("+"):
                # This is an added line
                changed_lines_per_file[current_file].add(current_line_in_hunk)
                current_line_in_hunk += 1
            elif line.startswith("-"):
                # This is a deleted line, we don't care about it for findings in the PR's current state
                pass
            else:
                # This is a context line
                current_line_in_hunk += 1

    return changed_lines_per_file


def get_changed_lines_with_gitpython(
    repo_path: str, base_ref: str, head_ref: str
) -> Dict[str, Set[int]]:
    """
    Uses GitPython to get changed lines (added or modified) between two refs.
    Returns a dictionary mapping file path to a set of changed line numbers.
    """
    repo = Repo(repo_path)

    # Get the commits for the base and head references
    try:
        base_commit = repo.commit(base_ref)
        head_commit = repo.commit(head_ref)
    except Exception as e:
        print(
            f"Error: Could not find base_ref '{base_ref}' or head_ref '{head_ref}'. {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    changed_lines_per_file = {}

    # Get the diff between the two commits
    # create_patch=True is important to get the line-by-line diff information
    diffs: List[Diff] = head_commit.diff(base_commit, create_patch=True)

    for diff_obj in diffs:
        # We are interested in the 'b' (new) side of the diff for finding locations
        file_path = diff_obj.b_path  # Path in the new commit
        if file_path is None:  # For deleted files, b_path is None
            continue

        changed_lines_per_file[file_path] = set()

        # Iterate through diff hunks and lines
        # GitPython's diff.diff attribute gives the raw diff string for the file.
        # We'll parse this string to get changed line numbers.
        # GitPython doesn't provide a direct way to get changed line numbers as integers
        # from Diff objects, so we still parse the hunk headers, but now the diff string
        # is guaranteed to be for the specific file and well-formed.

        lines = diff_obj.diff.splitlines()
        current_line_in_new_file = None

        hunk_header_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+),(\d+)? @@")

        for line_content in lines:
            hunk_match = hunk_header_re.match(line_content)
            if hunk_match:
                current_line_in_new_file = int(hunk_match.group(1))
                continue

            if current_line_in_new_file is not None:
                if line_content.startswith("+"):
                    # This is an added line
                    changed_lines_per_file[file_path].add(current_line_in_new_file)
                    current_line_in_new_file += 1
                elif line_content.startswith(" "):
                    # This is a context line
                    current_line_in_new_file += 1
                # Lines starting with '-' are deletions in the old file, don't increment new file line counter

    return changed_lines_per_file


def load_sarif(file_path: str) -> Dict:
    """Loads a SARIF file from the given path."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: SARIF file not found at '{file_path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in SARIF file '{file_path}'", file=sys.stderr)
        sys.exit(1)


def filter_findings_by_diff(
    sarif_data: Dict, changed_lines: Dict[str, Set[int]]
) -> List[Dict]:
    """
    Filters SARIF findings to include only those that overlap with changed lines.
    """
    filtered_findings = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations", [])
            if not locations:
                continue

            physical_location = locations[0].get("physicalLocation")
            if not physical_location:
                continue

            artifact_location = physical_location.get("artifactLocation")
            region = physical_location.get("region")

            if not artifact_location or not region:
                continue

            file_path = artifact_location.get(
                "uri"
            )  # SARIF uses URI, often looks like 'file:///path/to/repo/src/file.py'
            # Convert URI to a relative path that matches git diff output (e.g., 'src/file.py')
            # This is crucial for matching.
            if file_path and file_path.startswith("file://"):
                # Heuristic: Find the first occurrence of the actual file name
                # This might need refinement based on your repo structure.
                # A more robust way might involve knowing the repo root.
                repo_root_name = (
                    "pr_code/"  # The folder we checked out the PR into in the GHA
                )
                if repo_root_name in file_path:
                    file_path = file_path.split(repo_root_name, 1)[1]
                else:
                    # Fallback for simpler paths or if repo_root_name isn't in URI
                    file_path = file_path.split("/")[
                        -1
                    ]  # Just use filename as a last resort, might cause collisions

            start_line = region.get("startLine")
            end_line = region.get(
                "endLine", start_line
            )  # End line defaults to start if not present

            if file_path in changed_lines:
                # Check for overlap between finding's line range and changed lines
                for line_in_finding in range(start_line, end_line + 1):
                    if line_in_finding in changed_lines[file_path]:
                        filtered_findings.append(result)
                        break  # Found overlap, add result and move to next result
    return filtered_findings


def get_rule_name(sarif_data: Dict, rule_id: str) -> str:
    """Helper to get rule name from SARIF metadata."""
    for run in sarif_data.get("runs", []):
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        rules = driver.get("rules", [])
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule.get("name", rule_id)
    return rule_id


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python filter_semgrep_by_diff.py <head_sarif_file> <git_diff_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    head_sarif_path = sys.argv[1]
    git_diff_path = sys.argv[2]

    head_sarif = load_sarif(head_sarif_path)

    try:
        with open(git_diff_path, "r", encoding="utf-8") as f:
            git_diff_output = f.read()
    except FileNotFoundError:
        print(f"Error: Git diff file not found at '{git_diff_path}'", file=sys.stderr)
        sys.exit(1)

    changed_lines = parse_git_diff_lines(git_diff_output)

    filtered_findings = filter_findings_by_diff(head_sarif, changed_lines)

    if not filtered_findings:
        print("No Semgrep findings found on changed lines in this PR.")
        sys.exit(0)  # Success: No findings on changed lines

    print("Semgrep findings on changed lines:")

    # Need to access run's rule metadata for rule names
    sarif_data_for_rules = head_sarif  # Use the head_sarif to get rule names

    for finding in filtered_findings:
        rule_id = finding.get("ruleId", "N/A")
        message = finding.get("message", {}).get("text", "No message provided")
        location_uri = (
            finding.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri", "N/A")
        )
        start_line = (
            finding.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("region", {})
            .get("startLine", "N/A")
        )

        rule_name = get_rule_name(sarif_data_for_rules, rule_id)

        print(f"- Rule: {rule_name} ({rule_id})")
        print(f"  Location: {location_uri}:{start_line}")
        print(f"  Message: {message}")
        print("")

    sys.exit(1)  # Indicate failure: Findings on changed lines exist


if __name__ == "__main__":
    main()
