#!/usr/bin/env python3
"""Extract GitHub Issue Form field answers from an issue body.

GitHub renders each Issue Form field into the issue body as:

    ### <Label>

    <answer>

with "_No response_" when the field was left blank.

Reads the body from the ISSUE_BODY environment variable (never from argv or
directly interpolated into a shell script) so untrusted issue content can't
be used for command/script injection.

Usage:
  ISSUE_BODY="..." parse_issue_form.py ENV_NAME="Field Label" [ENV_NAME="Field Label" ...]

Prints "ENV_NAME=value" lines (value empty if unanswered) to stdout, suitable
for appending to $GITHUB_ENV.
"""
import os
import re
import sys


def extract_fields(body, labels):
    values = {}
    for label in labels:
        pattern = re.compile(
            r"^###\s*" + re.escape(label) + r"\s*\n+(.*?)(?=\n###\s|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(body)
        if not match:
            values[label] = ""
            continue
        value = match.group(1).strip()
        if value == "_No response_":
            value = ""
        values[label] = value.replace("\n", " ")
    return values


def main():
    if len(sys.argv) < 2:
        print("usage: parse_issue_form.py ENV_NAME=\"Field Label\" [...]", file=sys.stderr)
        sys.exit(1)

    pairs = []
    for arg in sys.argv[1:]:
        env_name, _, label = arg.partition("=")
        if not env_name or not label:
            print(f"invalid argument (expected ENV_NAME=Field Label): {arg}", file=sys.stderr)
            sys.exit(1)
        pairs.append((env_name, label))

    body = os.environ.get("ISSUE_BODY", "")
    values = extract_fields(body, [label for _, label in pairs])

    for env_name, label in pairs:
        print(f"{env_name}={values[label]}")


if __name__ == "__main__":
    main()
