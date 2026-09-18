// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package pamauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHelperPasswordOnStdin(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "pam")
	body := "#!/bin/sh\n" +
		"test \"$1\" = bootstashd || exit 1\n" +
		"test \"$2\" = alice || exit 1\n" +
		"p=$(cat)\n" +
		"test \"$p\" = secret || exit 1\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	h := Helper{Path: script, Service: "bootstashd"}
	if err := h.Authenticate("alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := h.Authenticate("alice", "wrong"); err != ErrDenied {
		t.Fatalf("got %v", err)
	}
	if err := h.Authenticate("bob", "secret"); err != ErrDenied {
		t.Fatalf("got %v", err)
	}
}

func TestValidService(t *testing.T) {
	if !ValidService("") || !ValidService("bootstashd") {
		t.Fatal("good names")
	}
	if ValidService("../sshd") || ValidService("a/b") {
		t.Fatal("paths")
	}
}

func TestValidUsername(t *testing.T) {
	if !ValidUsername("alice") || !ValidUsername("a.b_c-1") {
		t.Fatal("good names")
	}
	if ValidUsername("") || ValidUsername(".") || ValidUsername("..") || ValidUsername("a/b") {
		t.Fatal("bad names")
	}
}
