#!/usr/bin/env python3
"""Keep the Publish Policy dropdowns in sync with docs/.

Options are discovered from the docs/ directory tree:
  - policy_name choices   <- docs/<policy_name>/
  - minor_version choices <- docs/*/v<X.Y>/ (deduplicated across all policies)

An "Other" option is always appended so a value not yet present in docs/
can still be typed manually via the paired *_other text input.

Three files hold a copy of this data:
  - .github/policies/policy-options.json         (plain data, bot-writable)
  - .github/ISSUE_TEMPLATE/publish-policy.yml    (issue form, bot-writable)
  - .github/workflows/publish-policy.yml         (workflow_dispatch, NOT bot-writable)

GitHub blocks the default GITHUB_TOKEN from pushing changes to files under
.github/workflows/, so CI can only safely auto-commit the first two
(--ci-safe). Applying the same data to publish-policy.yml's dropdown is a
manual, human-reviewed step -- run this script with no flags locally and
commit/push the result yourself.

Modes:
  (no flags)  Refresh all three files. Run this locally after adding/removing
              a policy or version, then commit the changes.
  --ci-safe   Refresh only the two bot-writable files. Safe for CI to run and
              auto-commit.
  --check     Don't write anything. Exit 1 if publish-policy.yml's dropdown
              no longer matches docs/. Used by CI to flag drift.
"""
import argparse
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GITHUB_DIR = REPO_ROOT / ".github"
DOCS_DIR = REPO_ROOT / "docs"
WORKFLOW_FILE = GITHUB_DIR / "workflows" / "publish-policy.yml"
ISSUE_TEMPLATE_FILE = GITHUB_DIR / "ISSUE_TEMPLATE" / "publish-policy.yml"
DATA_FILE = GITHUB_DIR / "policies" / "policy-options.json"

WORKFLOW_BEGIN = "      # BEGIN AUTO-GENERATED INPUTS (from docs/ - run .github/scripts/generate_policy_inputs.py to refresh, do not edit by hand)"
WORKFLOW_END = "      # END AUTO-GENERATED INPUTS"

ISSUE_BEGIN = "  # BEGIN AUTO-GENERATED FIELDS (from docs/ - run .github/scripts/generate_policy_inputs.py to refresh, do not edit by hand)"
ISSUE_END = "  # END AUTO-GENERATED FIELDS"


def discover_policy_names():
    return sorted(p.name for p in DOCS_DIR.iterdir() if p.is_dir())


def discover_minor_versions():
    versions = set()
    for policy_dir in DOCS_DIR.iterdir():
        if not policy_dir.is_dir():
            continue
        for version_dir in policy_dir.iterdir():
            if version_dir.is_dir() and re.fullmatch(r"v\d+\.\d+", version_dir.name):
                versions.add(version_dir.name[1:])

    def sort_key(v):
        return tuple(int(part) for part in v.split("."))

    return sorted(versions, key=sort_key)


def yaml_scalar(value):
    # Quote anything YAML would otherwise coerce to a number/bool.
    if re.fullmatch(r"[0-9.]+", value) or value.lower() in {"true", "false", "null", "yes", "no"}:
        return f'"{value}"'
    return value


# ---------------------------------------------------------------------------
# publish-policy.yml (workflow_dispatch choice inputs)
# ---------------------------------------------------------------------------

def workflow_options_block(values):
    lines = [f"          - {yaml_scalar(v)}" for v in values]
    lines.append("          - Other")
    return "\n".join(lines)


def workflow_choice_input(name, description, values):
    return "\n".join([
        f"      {name}:",
        f"        description: '{description}'",
        "        required: true",
        "        type: choice",
        "        options:",
        workflow_options_block(values),
    ])


def workflow_other_input(name, description):
    return "\n".join([
        f"      {name}:",
        f"        description: '{description}'",
        "        required: false",
        "        type: string",
    ])


def build_workflow_block(policy_names, minor_versions):
    return "\n".join([
        WORKFLOW_BEGIN,
        workflow_choice_input(
            "policy_name",
            'Name of the policy to publish. Pick "Other" to type one manually.',
            policy_names,
        ),
        workflow_other_input(
            "policy_name_other",
            'Custom policy name (used only when "Other" is selected above)',
        ),
        workflow_choice_input(
            "minor_version",
            'Minor version (e.g., 0.1, 0.2). Pick "Other" to type one manually.',
            minor_versions,
        ),
        workflow_other_input(
            "minor_version_other",
            'Custom minor version (used only when "Other" is selected above)',
        ),
        WORKFLOW_END,
    ])


# ---------------------------------------------------------------------------
# .github/ISSUE_TEMPLATE/publish-policy.yml (issue form dropdown fields)
# ---------------------------------------------------------------------------

def issue_dropdown_field(field_id, label, description, values):
    lines = [
        "  - type: dropdown",
        f"    id: {field_id}",
        "    attributes:",
        f"      label: {label}",
        f"      description: {description}",
        "      options:",
    ]
    lines += [f"        - {yaml_scalar(v)}" for v in values]
    lines.append("        - Other")
    lines += [
        "    validations:",
        "      required: true",
    ]
    return "\n".join(lines)


def issue_input_field(field_id, label):
    return "\n".join([
        "  - type: input",
        f"    id: {field_id}",
        "    attributes:",
        f"      label: {label}",
        "    validations:",
        "      required: false",
    ])


def build_issue_block(policy_names, minor_versions):
    return "\n".join([
        ISSUE_BEGIN,
        issue_dropdown_field(
            "policy_name",
            "Policy name",
            'Name of the policy to publish. Pick "Other" to type one manually.',
            policy_names,
        ),
        issue_input_field(
            "policy_name_other",
            'Custom policy name (used only when "Other" is selected above)',
        ),
        issue_dropdown_field(
            "minor_version",
            "Minor version",
            'e.g., 0.1, 0.2. Pick "Other" to type one manually.',
            minor_versions,
        ),
        issue_input_field(
            "minor_version_other",
            'Custom minor version (used only when "Other" is selected above)',
        ),
        ISSUE_END,
    ])


# ---------------------------------------------------------------------------
# Generic marker-block helpers, shared by both files above
# ---------------------------------------------------------------------------

def extract_block(content, begin, end, file_label):
    if begin not in content or end not in content:
        print(f"Could not find auto-generated markers in {file_label}", file=sys.stderr)
        sys.exit(1)
    _, rest = content.split(begin, 1)
    middle, _ = rest.split(end, 1)
    return begin + middle + end


def apply_block(path, begin, end, new_block):
    content = path.read_text()
    current_block = extract_block(content, begin, end, str(path))

    if current_block == new_block:
        return False

    before, rest = content.split(begin, 1)
    _, after = rest.split(end, 1)
    path.write_text(before + new_block + after)
    return True


def block_matches(path, begin, end, expected_block):
    content = path.read_text()
    current_block = extract_block(content, begin, end, str(path))
    return current_block == expected_block


def write_data_file(policy_names, minor_versions):
    payload = {
        "policy_names": policy_names,
        "minor_versions": minor_versions,
    }
    text = json.dumps(payload, indent=2) + "\n"

    if DATA_FILE.exists() and DATA_FILE.read_text() == text:
        return False

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(text)
    return True


def sync_ci_safe_targets(policy_names, minor_versions):
    data_changed = write_data_file(policy_names, minor_versions)
    rel_data_file = DATA_FILE.relative_to(REPO_ROOT)
    print(f"Updated {rel_data_file}" if data_changed else f"{rel_data_file} already up to date")

    issue_block = build_issue_block(policy_names, minor_versions)
    issue_changed = apply_block(ISSUE_TEMPLATE_FILE, ISSUE_BEGIN, ISSUE_END, issue_block)
    rel_issue_file = ISSUE_TEMPLATE_FILE.relative_to(REPO_ROOT)
    print(f"Updated {rel_issue_file}" if issue_changed else f"{rel_issue_file} already up to date")


def check_workflow(policy_names, minor_versions):
    expected_block = build_workflow_block(policy_names, minor_versions)
    if block_matches(WORKFLOW_FILE, WORKFLOW_BEGIN, WORKFLOW_END, expected_block):
        print("publish-policy.yml dropdown is in sync with docs/")
        return True

    print(
        "publish-policy.yml's policy_name/minor_version dropdown is out of date "
        "with docs/.\nRun this locally and commit the result:\n"
        "  python3 .github/scripts/generate_policy_inputs.py",
        file=sys.stderr,
    )
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--ci-safe", action="store_true",
        help="Only refresh the bot-writable files (policy-options.json, ISSUE_TEMPLATE). Safe for CI to auto-commit.",
    )
    mode.add_argument(
        "--check", action="store_true",
        help="Check publish-policy.yml against docs/ without writing anything; exit 1 if stale.",
    )
    args = parser.parse_args()

    policy_names = discover_policy_names()
    minor_versions = discover_minor_versions()

    if not policy_names:
        print("No policy directories found under docs/", file=sys.stderr)
        sys.exit(1)

    if args.check:
        sys.exit(0 if check_workflow(policy_names, minor_versions) else 1)

    sync_ci_safe_targets(policy_names, minor_versions)

    if args.ci_safe:
        return

    workflow_block = build_workflow_block(policy_names, minor_versions)
    workflow_changed = apply_block(WORKFLOW_FILE, WORKFLOW_BEGIN, WORKFLOW_END, workflow_block)
    rel_workflow_file = WORKFLOW_FILE.relative_to(REPO_ROOT)
    print(f"Updated {rel_workflow_file}" if workflow_changed else f"{rel_workflow_file} already up to date")


if __name__ == "__main__":
    main()
