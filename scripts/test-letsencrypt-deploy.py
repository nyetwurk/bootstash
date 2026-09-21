#!/usr/bin/env python3
# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for contrib/letsencrypt-deploy. Run from the repo root (make test)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parents[1] / "contrib/letsencrypt-deploy"


class DeployHook(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.etc = root / "etc"
        self.live = root / "live"
        self.op = root / "default"
        self.etc.mkdir()
        self.live.mkdir()
        self.op.write_text("")
        self.err = ""

    def lineage(self, name: str) -> None:
        d = self.live / name
        d.mkdir()
        (d / "fullchain.pem").write_text(f"chain-{name}\n")
        (d / "privkey.pem").write_text(f"key-{name}\n")

    def dest(self, name: str) -> Path:
        return self.etc / "certs" / name / "fullchain.pem"

    def run_hook(
        self,
        *args: str,
        lineage: str | None = None,
        fqdn: str = "box.internal.example",
    ) -> None:
        env = {
            **os.environ,
            "BOOTSTASH_ETC": str(self.etc),
            "BOOTSTASH_DEFAULT": str(self.op),
            "BOOTSTASH_LIVE": str(self.live),
            "BOOTSTASH_FQDN": fqdn,
            "BOOTSTASH_GROUP": "nosuchgroup",
        }
        env.pop("RENEWED_LINEAGE", None)
        if lineage:
            env["RENEWED_LINEAGE"] = str(self.live / lineage)
        r = subprocess.run(
            [str(HOOK), *args], env=env, capture_output=True, text=True, check=False
        )
        self.out = r.stdout
        self.err = r.stderr
        self.assertEqual(r.returncode, 0, self.err)
        self.assertEqual(self.err, "")

    def test_cert_name_wins(self) -> None:
        self.lineage("stash.example")
        self.lineage("other.example")
        self.op.write_text("CERT_NAME=stash.example\n")
        self.run_hook("sync")
        self.assertTrue(self.dest("stash.example").is_file())
        self.assertFalse(self.dest("other.example").is_file())
        self.assertIn("using stash.example (CERT_NAME)", self.out)
        (self.etc / "certs" / "other.example").mkdir()
        self.run_hook("sync")
        self.assertFalse(self.dest("other.example").is_file())

    def test_public_url_host(self) -> None:
        self.lineage("stash.example")
        self.lineage("other.example")
        self.op.write_text("PUBLIC_URL=https://stash.example\n")
        self.run_hook("sync")
        self.assertTrue(self.dest("stash.example").is_file())
        self.assertFalse(self.dest("other.example").is_file())

    def test_hostname_f(self) -> None:
        self.lineage("box.example")
        self.run_hook("sync", fqdn="box.example")
        self.assertTrue(self.dest("box.example").is_file())
        self.assertIn("hostname -f", self.out)

    def test_only_lineage(self) -> None:
        self.lineage("box.example")
        self.run_hook("sync", fqdn="not-this.example")
        self.assertTrue(self.dest("box.example").is_file())

    def test_several_lineages_copy_nothing(self) -> None:
        self.lineage("a.example")
        self.lineage("b.example")
        self.run_hook("sync", fqdn="not-this.example")
        self.assertFalse(self.dest("a.example").is_file())
        self.assertFalse(self.dest("b.example").is_file())
        self.assertIn("live/ has:", self.out)
        self.assertIn("will not guess", self.out)

    def test_renew_chosen_only(self) -> None:
        self.lineage("a.example")
        self.lineage("b.example")
        self.op.write_text("CERT_NAME=a.example\n")
        self.run_hook(lineage="a.example")
        self.assertIn("copied", self.out)
        self.assertTrue(self.dest("a.example").is_file())
        self.assertFalse(self.dest("b.example").is_file())
        self.run_hook(lineage="b.example")
        self.assertEqual(self.out, "")
        self.assertFalse(self.dest("b.example").is_file())

    def test_renew_refreshes_installed(self) -> None:
        self.lineage("a.example")
        self.lineage("b.example")
        d = self.etc / "certs" / "b.example"
        d.mkdir(parents=True)
        (d / "fullchain.pem").write_text("stale\n")
        (d / "privkey.pem").write_text("stale\n")
        self.run_hook(lineage="b.example", fqdn="not-this.example")
        self.assertEqual(self.dest("b.example").read_text(), "chain-b.example\n")
        self.assertFalse(self.dest("a.example").is_file())

    def test_tls_no_purges(self) -> None:
        self.lineage("a.example")
        d = self.etc / "certs" / "a.example"
        d.mkdir(parents=True)
        (d / "fullchain.pem").write_text("leftover\n")
        (d / "privkey.pem").write_text("leftover\n")
        self.op.write_text("TLS=no\nCERT_NAME=a.example\n")
        self.run_hook("sync")
        self.assertFalse(self.dest("a.example").exists())
        self.assertFalse((d / "privkey.pem").exists())
        self.assertTrue((self.live / "a.example" / "privkey.pem").is_file())
        self.assertIn("TLS=no; not copying", self.out)

    def test_quoted_cert_name(self) -> None:
        self.lineage("a.example")
        self.op.write_text('CERT_NAME="a.example"\nTLS="auto"\n')
        self.run_hook("sync")
        self.assertTrue(self.dest("a.example").is_file())


if __name__ == "__main__":
    unittest.main()
