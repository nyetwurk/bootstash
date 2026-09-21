#!/usr/bin/env python3
# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for scripts/release.py version mapping. Run from repo root."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


release = load("release", HERE / "release.py")
changelog = load("debian_changelog", HERE / "debian-changelog.py")


class Version(unittest.TestCase):
    def test_exact_release(self) -> None:
        self.assertEqual(release.from_exact_tag("v0.0.3"), "0.0.3")
        self.assertIsNone(release.from_exact_tag("v0.0.3-7-g099e"))
        self.assertIsNone(release.from_exact_tag("foo"))

    def test_exact_rc(self) -> None:
        self.assertEqual(release.from_exact_tag("v0.0.3-rc1"), "0.0.3~rc1")

    def test_snapshot_after_release(self) -> None:
        self.assertEqual(release.from_describe("v0.0.3-7-g099e"), "0.0.3+git7.g099e")

    def test_snapshot_after_rc(self) -> None:
        self.assertEqual(
            release.from_describe("v0.0.3-rc1-2-gabcd"), "0.0.3~rc1+git2.gabcd"
        )

    def test_describe_is_the_tag(self) -> None:
        self.assertEqual(release.from_describe("v0.0.3"), "0.0.3")

    def test_no_tag(self) -> None:
        self.assertEqual(release.from_describe("099e"), "0.0.0+git.099e")

    def test_old_sanitized_shape(self) -> None:
        self.assertEqual(
            release.from_describe("v0.0.3.7.g099e"), "0.0.0+git.v0.0.3.7.g099e"
        )


class Suite(unittest.TestCase):
    def test_snapshot(self) -> None:
        self.assertEqual(changelog.suite_for("0.0.3+git7.g099e"), "UNRELEASED")

    def test_rc(self) -> None:
        self.assertEqual(changelog.suite_for("0.0.3~rc1"), "experimental")

    def test_release(self) -> None:
        self.assertEqual(changelog.suite_for("0.0.3"), "unstable")


if __name__ == "__main__":
    unittest.main()
