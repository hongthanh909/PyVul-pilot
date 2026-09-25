#!/usr/bin/env python3
"""Discover reviewed GitHub advisories for later dataset curation.

This script writes an inventory only. Its output is not model-ready and must
still pass source extraction, function-pair normalization, filtering, and
chunking before it may be merged into the training dataset.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import tempfile
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


API_URL = "https://api.github.com/advisories"
COMMIT_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,64})(?:[/?#].*)?$",
    re.IGNORECASE,
)


def fetch_advisories(cwe: int, ecosystem: str = "pip") -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"type": "reviewed", "ecosystem": ecosystem, "cwes": str(cwe), "per_page": 100}
    )
    url: str | None = f"{API_URL}?{query}"
    rows: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    while url and url not in seen_urls:
        seen_urls.add(url)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "PyVul-dataset-curation",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
            link = response.headers.get("Link", "")
        if not isinstance(payload, list):
            raise RuntimeError("GitHub advisory API returned an unexpected response")
        rows.extend(row for row in payload if isinstance(row, dict))
        url = next_link(link)
    # A defensive de-duplication keeps reruns deterministic if an advisory is
    # updated while cursor pagination is in progress.
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("ghsa_id") or row.get("html_url") or len(unique))
        unique[key] = row
    return list(unique.values())


def next_link(header: str) -> str | None:
    for item in header.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"', item)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


def normalize_candidate(advisory: Mapping[str, Any], cwe: int) -> dict[str, Any]:
    references = [str(value) for value in advisory.get("references") or []]
    commits: list[dict[str, str]] = []
    for url in references:
        match = COMMIT_RE.match(url)
        if not match:
            continue
        owner, repo, commit_id = match.groups()
        commits.append(
            {
                "repository": f"{owner}/{repo.removesuffix('.git')}",
                "commit_id": commit_id.lower(),
                "commit_url": url,
            }
        )

    exact_cwe = f"CWE-{cwe}"
    advisory_cwes = sorted(
        {
            str(row.get("cwe_id"))
            for row in advisory.get("cwes") or []
            if isinstance(row, Mapping) and row.get("cwe_id")
        }
    )
    if exact_cwe not in advisory_cwes:
        state = "REJECTED_CWE_MISMATCH"
    elif commits:
        state = "READY_FOR_EXTRACTION"
    else:
        state = "NEEDS_FIX_COMMIT"

    return {
        "candidate_schema_version": "1.0",
        "candidate_status": state,
        "target_cwe": exact_cwe,
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "summary": advisory.get("summary"),
        "advisory_url": advisory.get("html_url"),
        "source_code_location": advisory.get("source_code_location"),
        "github_reviewed_at": advisory.get("github_reviewed_at"),
        "published_at": advisory.get("published_at"),
        "cwes": advisory_cwes,
        "fix_commits": commits,
        "references": references,
    }


def atomic_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", delete=False, dir=path.parent
    ) as handle:
        temporary = Path(handle.name)
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    temporary.replace(path)


def write_summary(path: Path, candidates: list[dict[str, Any]]) -> None:
    counts = Counter(str(row["candidate_status"]) for row in candidates)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerow({"metric": "advisories_found", "value": len(candidates)})
        writer.writerow(
            {
                "metric": "unique_fix_commits",
                "value": len(
                    {
                        commit["commit_url"]
                        for row in candidates
                        for commit in row["fix_commits"]
                    }
                ),
            }
        )
        for status, count in sorted(counts.items()):
            writer.writerow({"metric": status, "value": count})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe", type=int, default=798)
    parser.add_argument("--ecosystem", default="pip")
    parser.add_argument("--output-dir", type=Path, default=Path("data/supplement/cwe-798"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    advisories = fetch_advisories(args.cwe, args.ecosystem)
    candidates = [normalize_candidate(row, args.cwe) for row in advisories]
    candidates.sort(key=lambda row: (str(row["candidate_status"]), str(row["ghsa_id"])))
    atomic_jsonl(args.output_dir / "advisory_candidates.jsonl", candidates)
    write_summary(args.output_dir / "discovery_summary.csv", candidates)
    counts = Counter(str(row["candidate_status"]) for row in candidates)
    print(f"Found {len(candidates)} reviewed advisories for CWE-{args.cwe}/{args.ecosystem}")
    for status, count in sorted(counts.items()):
        print(f"{status}: {count}")
    print(f"Wrote candidate inventory to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
