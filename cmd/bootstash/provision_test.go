// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteSecretsFileDoesNotTouchOperatorConfig(t *testing.T) {
	dir := t.TempDir()
	op := filepath.Join(dir, "config")
	sec := filepath.Join(dir, "oidc-google")
	if err := os.WriteFile(op, []byte("PUBLIC_ORIGIN=https://stash.test\nBIND=lo:8080\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretsFile(sec, map[string]string{
		"OIDC_GOOGLE_CLIENT_ID":     "cid",
		"OIDC_GOOGLE_CLIENT_SECRET": "sekrit",
	}, ""); err != nil {
		t.Fatal(err)
	}
	opBody, err := os.ReadFile(op)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(opBody), "OIDC_GOOGLE") {
		t.Fatalf("operator config mutated: %s", opBody)
	}
	secBody, err := os.ReadFile(sec)
	if err != nil {
		t.Fatal(err)
	}
	got := string(secBody)
	if !strings.Contains(got, "OIDC_GOOGLE_CLIENT_ID=cid") || !strings.Contains(got, "OIDC_GOOGLE_CLIENT_SECRET=sekrit") {
		t.Fatalf("secrets %s", got)
	}
	if strings.Contains(got, "BIND=") || strings.Contains(got, "PUBLIC_ORIGIN=") {
		t.Fatalf("secrets mixed with operator keys: %s", got)
	}
	st, err := os.Stat(sec)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0640 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestWriteSecretsFileUpserts(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "oidc-google")
	if err := writeSecretsFile(sec, map[string]string{
		"OIDC_GOOGLE_CLIENT_ID":     "old",
		"OIDC_GOOGLE_CLIENT_SECRET": "oldsec",
	}, ""); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretsFile(sec, map[string]string{
		"OIDC_GOOGLE_CLIENT_ID":     "new",
		"OIDC_GOOGLE_CLIENT_SECRET": "newsec",
	}, ""); err != nil {
		t.Fatal(err)
	}
	secBody, err := os.ReadFile(sec)
	if err != nil {
		t.Fatal(err)
	}
	got := string(secBody)
	if strings.Count(got, "OIDC_GOOGLE_CLIENT_ID=") != 1 || !strings.Contains(got, "OIDC_GOOGLE_CLIENT_ID=new") {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, "oldsec") || !strings.Contains(got, "OIDC_GOOGLE_CLIENT_SECRET=newsec") {
		t.Fatalf("%s", got)
	}
}
