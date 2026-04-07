#!/usr/bin/env python3
# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------
"""Generate docs/README.md policy catalog table from docs/<policy>/<version>/metadata.json.

Usage:
  generate-policy-catalog.py           # write docs/README.md
  generate-policy-catalog.py --validate # exit 1 if docs/README.md is out of date
"""

import json
import re
import sys
from pathlib import Path

DOCS_DIR = Path(__file__).parent.parent / "docs"
OUTPUT = DOCS_DIR / "README.md"


def latest_version(versions):
    def key(v):
        return [int(x) for x in v.lstrip("v").split(".")]
    return sorted(versions, key=key)[-1]


def first_sentence(text):
    flat = re.sub(r"\s+", " ", text.strip())
    m = re.search(r"^(.+?[.!?])\s", flat)
    return m.group(1) if m else flat.split(".")[0].strip() + "."


def build_catalog():
    policies = []

    for entry in sorted(DOCS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        versions = [d.name for d in entry.iterdir() if d.is_dir()]
        if not versions:
            continue

        ver = latest_version(versions)
        meta_path = entry / ver / "metadata.json"
        if not meta_path.exists():
            continue

        with open(meta_path) as f:
            meta = json.load(f)

        docs_subdir = entry / ver / "docs"
        doc_files = sorted(docs_subdir.glob("*.md")) if docs_subdir.exists() else []
        doc_file = doc_files[0].name if doc_files else None
        link = f"./{entry.name}/{ver}/docs/{doc_file}" if doc_file else None

        policies.append({
            "name": meta.get("displayName", entry.name),
            "link": link,
            "categories": meta.get("categories", []),
            "description": first_sentence(meta.get("description", "")),
        })

    policies.sort(key=lambda p: p["name"].lower())

    lines = [
        "# Policy Catalog",
        "",
        "All available policies in the Gateway Controllers Policy Hub, sorted alphabetically.",
        "",
        "| Policy | Categories | Description |",
        "|--------|------------|-------------|",
    ]

    for p in policies:
        name_cell = f"[{p['name']}]({p['link']})" if p["link"] else p["name"]
        cats = ", ".join(p["categories"])
        lines.append(f"| {name_cell} | {cats} | {p['description']} |")

    lines.append("")
    return "\n".join(lines)


def main():
    check_mode = "--validate" in sys.argv
    content = build_catalog()

    if check_mode:
        if not OUTPUT.exists():
            print(f"error: {OUTPUT} does not exist. Run 'make generate-catalog' to create it.")
            sys.exit(1)
        current = OUTPUT.read_text()
        if current == content:
            print(f"{OUTPUT} is up to date.")
        else:
            print(f"error: {OUTPUT} is out of date. Run 'make generate-catalog' to regenerate it.")
            sys.exit(1)
    else:
        OUTPUT.write_text(content)
        print(f"Generated {OUTPUT}")


if __name__ == "__main__":
    main()
