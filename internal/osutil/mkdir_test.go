// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package osutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMkdirOwnerCreatesAndRepeats(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users")
	if err := os.Mkdir(users, 0711); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if err := MkdirOwner(users, "alice", uid, gid); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(users, "alice")
	st, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		t.Fatalf("mode %s", st.Mode())
	}
	if st.Mode()&os.ModeSetgid == 0 || st.Mode().Perm() != 0770 {
		t.Fatalf("want 02770, got %s", st.Mode())
	}
	if err := MkdirOwner(users, "alice", uid, gid); err != nil {
		t.Fatal(err)
	}
}

func TestMkdirOwnerRejectsEscapeAndSymlink(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users")
	if err := os.Mkdir(users, 0711); err != nil {
		t.Fatal(err)
	}
	if err := MkdirOwner(users, "../etc", os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("expected reject")
	}
	link := filepath.Join(users, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if err := MkdirOwner(users, "link", os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("symlink must be refused")
	}
}
