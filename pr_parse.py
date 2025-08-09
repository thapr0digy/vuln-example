import json
import logging
import os
import re
import requests
import sys
from github import Auth, Github
from typing import Dict, List, Set

from github.Commit import Commit
from github.PullRequest import PullRequest, ReviewComment

# Constants
SEMGREP_PLAYGROUND_URL = "https://semgrep.dev/playground/r"

logger = logging.getLogger(__name__)

# Retrieve all necessary environment variables
commit_url = os.environ["COMMIT_URL"]
repo_name = os.environ["REPOSITORY"]
commit_id = os.environ["COMMIT_ID"]
event_num = int(os.environ["EVENT_NUM"])
gh_token = os.environ["GITHUB_TOKEN"]


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

    current_line_in_hunk = None
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

            file_path = artifact_location.get("uri")
            # Convert URI to a relative path that matches git diff output (e.g., 'src/file.py')
            # This is crucial for matching.
            if file_path:
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


def get_rule_severity(rule_id: str) -> str:
    """
    Generates the severity for the finding using the rule id
    """
    semgrep_registry_url = (
        f"https://semgrep.dev/api/registry/rules/{rule_id}?definition=1"
    )
    sess = requests.Session()
    response = sess.get(semgrep_registry_url)
    body = response.json()
    severity = body["definition"]["rules"][0].get("severity", "").lower()
    likelihood = (
        body["definition"]["rules"][0]["metadata"].get("likelihood", "").lower()
    )
    impact = body["definition"]["rules"][0]["metadata"].get("impact", "").lower()
    confidence = (
        body["definition"]["rules"][0]["metadata"].get("confidence", "").lower()
    )

    pattern = (severity, likelihood, impact, confidence)

    match pattern:
        case ("error", "high", "high", _):
            return "Critical"

        case ("error", _, _, _) | (_, "high", "high", _):
            return "High"

        case ("warning", _, _, _) | (_, "high", "medium", _) | (_, "medium", "high", _):
            return "Medium"

        case (_, "low", _, _) | (_, _, "low", _) | (_, _, _, "low"):
            return "Low"

        case _:
            return "Informational"


def create_review_findings(
    pr: PullRequest, commit: Commit, findings: List[Dict]
) -> None:
    review_comments = []

    commit_message = f"""### New Opengrep SAST Findings:\nThis PR introduced **{len(findings)}** potential security finding(s).\nPlease review these findings and address them before merging."""

    for finding in findings:
        semgrep_rule_url = (
            f"{SEMGREP_PLAYGROUND_URL}/{finding['ruleId']}?editorMode=advanced"
        )
        file_location = f"{commit_url}/{finding['location']}#L{finding['start_line']}-L{finding['end_line']}"
        comment_message = f"""**Rule:** [{finding["ruleId"]}]({semgrep_rule_url})
        \t**Severity:** {finding["severity"]}
        \t**Location:** [{finding["location"]}:{finding["start_line"]}]({file_location})
        \t**Message:** {finding["message"]}
        """
        review_comment = ReviewComment(
            path=finding["location"],
            body=comment_message,
            start_line=finding["start_line"],
            line=finding["end_line"],
        )
        review_comments.append(review_comment)
    pr.create_review(
        commit=commit, body=commit_message, event="COMMENT", comments=review_comments
    )


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python opengrep_diff.py <head_sarif_file> <git_diff_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    head_sarif_path = sys.argv[1]
    git_diff_path = sys.argv[2]

    if not gh_token:
        logging.info("Github token not provided. Exiting")
        sys.exit(1)

    auth = Auth.Token(gh_token)
    gh_client = Github(auth=auth)

    head_sarif = load_sarif(head_sarif_path)

    # Perform diff logic
    try:
        with open(git_diff_path, "r", encoding="utf-8") as f:
            git_diff_output = f.read()
    except FileNotFoundError:
        print(f"Error: Git diff file not found at '{git_diff_path}'", file=sys.stderr)
        sys.exit(1)

    changed_lines = parse_git_diff_lines(git_diff_output)

    filtered_findings = filter_findings_by_diff(head_sarif, changed_lines)

    # Prepare output for GitHub Actions
    output_data = {}

    if not filtered_findings:
        print("No Opengrep findings found on changed lines in this PR.")
        output_data["status"] = "success"
        output_data["findings_summary"] = (
            "No new Opengrep findings found on changed lines in this PR."
        )
        output_data["findings_count"] = 0

        # Write outputs to GITHUB_OUTPUT
        with open(os.environ["GITHUB_OUTPUT"], "a") as gh_output:
            gh_output.write(f"status={output_data['status']}\n")
            gh_output.write(f"findings_count={output_data['findings_count']}\n")
            # For multi-line output, use a delimiter
            gh_output.write("findings_summary<<EOF\n")
            gh_output.write(output_data["findings_summary"] + "\n")
            gh_output.write("EOF\n")
        sys.exit(0)  # Success: No findings on changed lines

    # Need to access run's rule metadata for rule names
    findings_for_output = []
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

        end_line = (
            finding.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("region", {})
            .get("endLine", "N/A")
        )
        rule_name = get_rule_name(sarif_data_for_rules, rule_id)
        severity = get_rule_severity(rule_id)

        findings_for_output.append(
            {
                "ruleName": rule_name,
                "ruleId": rule_id,
                "severity": severity,
                "location": location_uri,
                "start_line": start_line,
                "end_line": end_line,
                "message": message,
            }
        )

    output_data["status"] = "failure"
    output_data["findings_count"] = len(findings_for_output)

    # Add PR comments using GitHub API
    gh_repo = gh_client.get_repo(repo_name)
    gh_pr = gh_repo.get_pull(event_num)
    gh_commit = gh_repo.get_commit(commit_id)
    create_review_findings(gh_pr, gh_commit, findings_for_output)

    # Create a markdown summary for the PR comment
    markdown_summary = []
    markdown_summary.append("### New Opengrep Findings on Changed Lines\n")
    markdown_summary.append(
        f"This PR introduced **{len(findings_for_output)}** potential security finding(s) on changed lines:\n"
    )
    for f in findings_for_output:
        semgrep_rule_url = f"{SEMGREP_PLAYGROUND_URL}/{f['ruleId']}?editorMode=advanced"

        file_location = (
            f"{commit_url}/{f['location']}#L{f['start_line']}-L{f['end_line']}"
        )

        markdown_summary.append(f"1. **Rule:** [{f['ruleId']}]({semgrep_rule_url})\n")
        markdown_summary.append(
            f"\tLocation: [{f['location']}:{f['start_line']}]({file_location})\n"
        )
        markdown_summary.append(f"\tMessage: {f['message']}\n")
        markdown_summary.append(
            "\nPlease review these findings and address them before merging. Report any feedback or questions to #appsec"
        )

    output_data["findings_summary"] = "\n".join(markdown_summary)

    # Write outputs to GITHUB_OUTPUT
    with open(os.environ["GITHUB_OUTPUT"], "a") as gh_output:
        gh_output.write(f"status={output_data['status']}\n")
        gh_output.write(f"findings_count={output_data['findings_count']}\n")
        gh_output.write("findings_summary<<EOF\n")
        gh_output.write(output_data["findings_summary"] + "\n")
        gh_output.write("EOF\n")

    print(markdown_summary)


if __name__ == "__main__":
    main()
