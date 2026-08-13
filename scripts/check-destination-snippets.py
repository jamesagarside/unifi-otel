#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate every gateway config snippet in docs/destinations.md.

This is the mechanism that lets contributed destinations be accepted
without the maintainer running the backend. `otelcol validate` proves a
snippet parses and that every component it names exists in the pinned
image. It does NOT prove records arrive anywhere -- that is the point,
and it is exactly the line drawn in issue #14: destinations are
documentation, weighted equally, and the maintainer runs one of them.

Without this check the snippets rot silently. Exporter names and config
keys move between collector releases -- the `loki` exporter was removed
from contrib outright, `logs_dynamic_index::enabled` became a no-op, and
`mapping::mode` is on its way out -- so a doc full of copy-pasteable
YAML is a doc full of things that will stop working without anyone
noticing.

Not every fenced block is a whole config. A block with no top-level
`service:` key is a fragment illustrating one stanza, and validating it
would fail for reasons that say nothing about the snippet's quality.
Fragments are REPORTED rather than silently skipped: a snippet that
stops being a whole config because someone trimmed it is a real change,
and a checker that quietly validates fewer things over time is worse
than no checker.

Usage:
    python3 scripts/check-destination-snippets.py
    python3 scripts/check-destination-snippets.py --image otel/...:0.157.0
    python3 scripts/check-destination-snippets.py --doc docs/destinations.md

Exit codes:
    0  every full config validated
    1  at least one snippet failed to validate
    2  usage/environment error (doc missing, docker unavailable, no
       snippets found -- the last is a failure, not a pass, because a
       silent zero would look identical to success)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOC = REPO_ROOT / "docs" / "destinations.md"
DEFAULT_COMPOSE = REPO_ROOT / "docker-compose.yml"

FENCE = re.compile(r"^```yaml\s*$(.*?)^```\s*$", re.M | re.S)
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$", re.M)


def pinned_image() -> str:
    """Read the collector tag from docker-compose.yml.

    Deliberately not a constant: the pin lives in one place and this
    check must follow it, or it will keep proving the snippets work
    against a version nobody ships.
    """
    try:
        text = DEFAULT_COMPOSE.read_text()
    except OSError:
        return "otel/opentelemetry-collector-contrib:0.157.0"
    m = re.search(r"image:\s*(otel/opentelemetry-collector-contrib:\S+)", text)
    return m.group(1) if m else "otel/opentelemetry-collector-contrib:0.157.0"


def nearest_heading(text: str, pos: int) -> str:
    """The closest heading above `pos`, for naming the snippet."""
    best = "(no heading)"
    for m in HEADING.finditer(text):
        if m.start() > pos:
            break
        best = m.group(1)
    return best


def extract(doc: Path) -> list[tuple[str, str]]:
    text = doc.read_text()
    out = []
    for m in FENCE.finditer(text):
        out.append((nearest_heading(text, m.start()), m.group(1)))
    return out


def is_full_config(snippet: str) -> bool:
    """A whole config has a top-level `service:` key.

    Checked at column zero: a nested `service:` (say, under a resource
    attribute) is not the same thing.
    """
    return any(line.startswith("service:") for line in snippet.splitlines())


ENV_REF = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}")


def referenced_env(snippet: str) -> list[str]:
    """Every ${env:VAR} the snippet names.

    Discovered rather than hardcoded, deliberately. A hardcoded list
    only covers the destinations that exist today, and this check exists
    precisely so CONTRIBUTED destinations can be accepted -- a
    contributor naming their variable something unforeseen would
    otherwise get a failure that looks like a broken snippet but is
    really a stale list here. That already happened once during
    development, with SPLUNK_HEC_TOKEN against a guessed SPLUNK_TOKEN.

    Values are irrelevant; validate only needs them non-empty, since an
    empty expansion produces "requires a non-empty ..." and would
    masquerade as a genuine config error.
    """
    return sorted(set(ENV_REF.findall(snippet)))


def validate(snippet: str, image: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "snippet.yaml"
        cfg.write_text(snippet)
        # tempfile creates the directory 0700 owned by the current user.
        # The contrib image runs as uid 10001, so on Linux it cannot
        # traverse the mount and every snippet fails with "permission
        # denied" -- which reads exactly like a broken snippet.
        #
        # This does NOT reproduce on macOS: Docker Desktop's filesystem
        # mapping hides the uid mismatch, so the check passes locally and
        # fails on every CI runner. Found precisely that way.
        #
        # 0755/0644 is safe here: the content is a documentation snippet
        # already public in the repo, and the directory is discarded on
        # exit.
        os.chmod(td, 0o755)
        os.chmod(cfg, 0o644)
        env_args = []
        for var in referenced_env(snippet):
            env_args += ["-e", f"{var}=ci-not-a-real-secret"]
        try:
            proc = subprocess.run(
                [
                    "docker", "run", "--rm",
                    *env_args,
                    "-v", f"{td}:/snip:ro",
                    image, "validate", "--config=/snip/snippet.yaml",
                ],
                capture_output=True, text=True, timeout=120,
            )
        except FileNotFoundError:
            print("docker not found on PATH", file=sys.stderr)
            sys.exit(2)
        except subprocess.TimeoutExpired:
            return False, "timed out after 120s"
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    ap.add_argument("--image", default=None,
                    help="collector image; defaults to the docker-compose.yml pin")
    args = ap.parse_args()

    if not args.doc.is_file():
        print(f"no such file: {args.doc}", file=sys.stderr)
        return 2

    image = args.image or pinned_image()
    snippets = extract(args.doc)
    if not snippets:
        print(f"no ```yaml blocks found in {args.doc} -- refusing to report "
              f"success on zero snippets", file=sys.stderr)
        return 2

    print(f"checking {len(snippets)} snippet(s) from {args.doc} against {image}\n")

    failed = 0
    checked = 0
    for heading, snippet in snippets:
        if not is_full_config(snippet):
            print(f"  [SKIP] {heading} -- fragment, no top-level service: key")
            continue
        checked += 1
        ok, output = validate(snippet, image)
        if ok:
            print(f"  [PASS] {heading}")
        else:
            failed += 1
            print(f"  [FAIL] {heading}")
            for line in output.splitlines():
                print(f"         {line}")

    print()
    if checked == 0:
        print("every block was a fragment -- nothing was actually validated",
              file=sys.stderr)
        return 2
    if failed:
        print(f"check-destination-snippets: FAIL -- {failed} of {checked} "
              f"snippet(s) did not validate")
        return 1
    print(f"check-destination-snippets: OK -- {checked} snippet(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
