#!/usr/bin/env python3
# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render debian/changelog stanzas from git-cliff --context JSON."""

from __future__ import annotations

import email.utils
import json
import re
import subprocess
import sys
import textwrap
import time

MAINTAINER = "nyet <nyet@nyet.org>"
CHANGELOG_WIDTH = 80
# GitHub Actions pull_request checkout: "Merge <sha> into <sha>".
_GH_SHA_MERGE = re.compile(r"^Merge [0-9a-f]{7,40} into [0-9a-f]{7,40}$", re.I)
_GH_PR_MERGE = re.compile(r"^Merge pull request #\d+\b")


def tag_to_deb(tag: str) -> str:
    if tag.startswith("v"):
        tag = tag[1:]
    return tag.replace("-rc", "~rc", 1)


def suite_for(ver: str) -> str:
    if "+git" in ver:
        return "UNRELEASED"
    if "~rc" in ver:
        return "experimental"
    return "unstable"


def first_line(msg: str) -> str:
    return msg.split("\n", 1)[0].strip()


def is_merge_commit(raw: dict) -> bool:
    if raw.get("merge_commit") is True:
        return True
    for key in ("message", "raw_message"):
        line = first_line(str(raw.get(key) or ""))
        if _GH_SHA_MERGE.match(line) or _GH_PR_MERGE.match(line):
            return True
    return False


def wrap_bullet(msg: str) -> list[str]:
    wrapper = textwrap.TextWrapper(
        width=CHANGELOG_WIDTH,
        initial_indent="  * ",
        subsequent_indent="    ",
        break_long_words=False,
        break_on_hyphens=False,
        replace_whitespace=True,
        drop_whitespace=True,
    )
    return wrapper.wrap(msg)


def rfc2822(ts: object, commit_id: str) -> str:
    if isinstance(ts, (int, float)) and ts > 0:
        if ts > 1e12:
            ts = ts / 1000.0
        return email.utils.formatdate(ts, localtime=True)
    if commit_id:
        try:
            out = subprocess.check_output(
                ["git", "log", "-1", "--format=%cD", commit_id],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            date = out.strip()
            if date:
                return date
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            pass
    return email.utils.formatdate(time.time(), localtime=True)


def bullets(commits: list[object]) -> list[str]:
    seen: set[str] = set()
    lines: list[str] = []
    for raw in commits:
        if not isinstance(raw, dict):
            continue
        if is_merge_commit(raw):
            continue
        msg = first_line(str(raw.get("message") or ""))
        if not msg or msg in seen:
            continue
        wrapped = wrap_bullet(msg)
        if not wrapped:
            continue
        seen.add(msg)
        lines.extend(wrapped)
    if not lines:
        lines.append("  * Development build.")
    return lines


def stanza(ver: str, commits: list[object], ts: object, commit_id: str) -> str:
    body = "\n".join(bullets(commits))
    date = rfc2822(ts, commit_id)
    return (
        f"bootstash ({ver}) {suite_for(ver)}; urgency=medium\n"
        f"\n"
        f"{body}\n"
        f"\n"
        f" -- {MAINTAINER}  {date}\n"
    )


def fallback(ver: str) -> str:
    return stanza(ver, [], None, "")


def releases_from(data: object) -> list[dict]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        inner = data.get("releases")
        if isinstance(inner, list):
            return [r for r in inner if isinstance(r, dict)]
        return [data]
    return []


def main() -> int:
    current = sys.argv[1] if len(sys.argv) > 1 else "0.0.0+git.unknown"
    raw = sys.stdin.read().strip()
    if not raw:
        sys.stdout.write(fallback(current))
        return 0
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        sys.stdout.write(fallback(current))
        return 0

    stanzas: list[str] = []
    seen_ver: set[str] = set()
    for rel in releases_from(data):
        tag = rel.get("version")
        if isinstance(tag, str) and tag:
            ver = tag_to_deb(tag)
        else:
            ver = current
        if ver in seen_ver:
            continue
        seen_ver.add(ver)
        commits = rel.get("commits")
        if not isinstance(commits, list):
            commits = []
        stanzas.append(
            stanza(ver, commits, rel.get("timestamp"), str(rel.get("commit_id") or ""))
        )

    if current not in seen_ver:
        stanzas.insert(0, fallback(current))
    if not stanzas:
        stanzas.append(fallback(current))
    sys.stdout.write("\n".join(stanzas))
    if not stanzas[-1].endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
