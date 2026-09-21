#!/usr/bin/env python3
# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later
"""Debian version and release notes from git tags.

version [packaged]  → Debian version on stdout
github              → git-cliff markdown (GitHub release body)
debian              → debian/changelog
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG_PY = Path(__file__).resolve().parent / "debian-changelog.py"
DEBIAN_CHANGELOG = ROOT / "debian/changelog"

# vX.Y.Z or vX.Y.Z-rcN (legal tags). git describe: that, plus -N-gSHA.
_LEGAL = re.compile(r"^v(\d+\.\d+\.\d+)(?:-rc(\d+))?$")
_DESCRIBE = re.compile(
    r"^v(\d+\.\d+\.\d+)(?:-rc(\d+))?(?:-(\d+)-g([0-9a-f]+))?$"
)
_RELEASE_TAGS = r"^v[0-9]+\.[0-9]+\.[0-9]+$"


def git(*args: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", *args],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    return out.strip()


def in_git() -> bool:
    return git("rev-parse", "--is-inside-work-tree") == "true"


def from_exact_tag(tag: str) -> str | None:
    m = _LEGAL.fullmatch(tag)
    if not m:
        return None
    ver = m.group(1)
    if m.group(2):
        return f"{ver}~rc{m.group(2)}"
    return ver


def from_describe(desc: str) -> str:
    """v0.0.3-7-g099e → 0.0.3+git7.g099e. No legal ancestor → 0.0.0+git.*"""
    m = _DESCRIBE.fullmatch(desc)
    if not m:
        safe = re.sub(r"[^A-Za-z0-9.+~]", ".", desc).strip(".")
        return f"0.0.0+git.{safe}" if safe else "0.0.0+git.unknown"
    base, rc, n, sha = m.group(1), m.group(2), m.group(3), m.group(4)
    ver = f"{base}~rc{rc}" if rc else base
    if n is None:
        return ver
    return f"{ver}+git{n}.g{sha}"


def packaged_version() -> str:
    if DEBIAN_CHANGELOG.is_file():
        for line in DEBIAN_CHANGELOG.read_text().splitlines():
            m = re.match(r"^bootstash \(([^)]+)\)", line)
            if m:
                return m.group(1)
    return debian_version()


def debian_version() -> str:
    if in_git():
        tag = git("describe", "--tags", "--exact-match")
        if tag:
            exact = from_exact_tag(tag)
            if exact is not None:
                return exact
        desc = git("describe", "--tags", "--abbrev=4", "--always")
        if desc:
            return from_describe(desc)
    return "0.0.0+git.unknown"


def github_notes() -> int:
    if not shutil.which("git-cliff"):
        print("release.py: git-cliff is required", file=sys.stderr)
        return 1
    if not in_git():
        print("release.py: not a git repository", file=sys.stderr)
        return 1
    tag = git("describe", "--tags", "--exact-match") or ""
    legal = _LEGAL.fullmatch(tag)
    cmd = ["git-cliff", "--strip", "header"]
    if legal and not legal.group(2):
        cmd.extend(["--current", "--tag-pattern", _RELEASE_TAGS])
    elif legal:
        cmd.append("--current")
    else:
        cmd.append("--unreleased")
    return subprocess.call(cmd, cwd=ROOT)


def debian_notes(ver: str) -> int:
    py = [sys.executable, str(CHANGELOG_PY), ver]
    if shutil.which("git-cliff") and in_git():
        ctx = subprocess.run(
            ["git-cliff", "--context", "--offline"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if ctx.returncode == 0:
            r = subprocess.run(py, cwd=ROOT, input=ctx.stdout, text=True)
            if r.returncode == 0:
                return 0
    return subprocess.run(py, cwd=ROOT, input="", text=True).returncode


def usage() -> int:
    print("usage: release.py version [packaged] | github | debian", file=sys.stderr)
    return 2


def main(argv: list[str]) -> int:
    if not argv:
        return usage()
    cmd = argv[0]
    if cmd == "version":
        if argv[1:] == ["packaged"]:
            print(packaged_version())
            return 0
        if argv[1:]:
            return usage()
        print(debian_version())
        return 0
    if cmd == "github":
        if argv[1:]:
            return usage()
        return github_notes()
    if cmd == "debian":
        if argv[1:]:
            return usage()
        return debian_notes(debian_version())
    return usage()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
