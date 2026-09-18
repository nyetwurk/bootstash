// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nyet/bootstash/internal/store"
)

func TestListLinksPrintsPAMIssuerSub(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(op, []byte("DATA="+data+"\nPUBLIC_URL=https://stash.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://accounts.google.com"
	if err := st.SetLink(iss, "sub-bob", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLink(iss, "sub-2", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLink(iss, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}

	args := []string{"-defaults", filepath.Join(dir, "missing-dist"), "-config", op, "-secrets", filepath.Join(dir, "missing-secrets")}
	var buf bytes.Buffer
	if code := listLinks(&buf, args); code != 0 {
		t.Fatalf("links: %d", code)
	}
	got := buf.String()
	want := "alice " + iss + " sub-1\nalice " + iss + " sub-2\nbob " + iss + " sub-bob\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if code := listLinks(&buf, append(args, "alice")); code != 2 {
		t.Fatalf("extra arg: %d", code)
	}
}

func TestListLinksEmpty(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(op, []byte("DATA="+data+"\nPUBLIC_URL=https://stash.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(data); err != nil {
		t.Fatal(err)
	}
	args := []string{"-defaults", filepath.Join(dir, "missing-dist"), "-config", op, "-secrets", filepath.Join(dir, "missing-secrets")}
	var buf bytes.Buffer
	if code := listLinks(&buf, args); code != 0 {
		t.Fatalf("empty: %d", code)
	}
	if buf.Len() != 0 {
		t.Fatalf("empty output %q", buf.String())
	}
	if strings.Contains(buf.String(), "@") {
		t.Fatal("email is not a column")
	}
}
