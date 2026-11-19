// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintConfig(t *testing.T) {
	dir := t.TempDir()
	op := filepath.Join(dir, "op")
	if err := os.WriteFile(op, []byte("PAM=no\nALLOWED_EMAILS=bob@gmail.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "sec")
	if err := os.WriteFile(sec, []byte("OIDC_GOOGLE_CLIENT_SECRET=super\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code := printConfig(&buf, []string{
		"-defaults", filepath.Join(dir, "missing-dist"),
		"-config", op,
		"-secrets", sec,
	})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "PAM=no\n") || !strings.Contains(out, "ALLOWED_EMAILS=bob@gmail.com\n") {
		t.Fatalf("%s", out)
	}
	if strings.Contains(out, "super") {
		t.Fatalf("secret printed\n%s", out)
	}
	if err := os.Chmod(sec, 0); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	code = printConfig(&buf, []string{
		"-defaults", filepath.Join(dir, "missing-dist"),
		"-config", op,
		"-secrets", sec,
	})
	if code != 0 {
		t.Fatalf("unreadable secrets exit %d", code)
	}
	if !strings.Contains(buf.String(), "ALLOWED_EMAILS=bob@gmail.com\n") {
		t.Fatalf("unreadable secrets dropped operator config\n%s", buf.String())
	}
	if code := printConfig(&buf, []string{"extra"}); code != 2 {
		t.Fatalf("exit %d", code)
	}
}
