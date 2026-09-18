// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package osutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChmodNoopAndChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Chmod(p, 0640); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0640 {
		t.Fatalf("%04o", st.Mode().Perm())
	}
}

func TestConfine(t *testing.T) {
	dir := t.TempDir()
	inside := filepath.Join(dir, "a")
	got, err := Confine(dir, inside)
	if err != nil || got != filepath.Clean(inside) {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := Confine(dir, filepath.Join(dir, "..", "outside")); err == nil {
		t.Fatal("escape")
	}
}

func TestChmodInRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "outside")
	if err := ChmodIn(dir, outside, 0600); err == nil {
		t.Fatal("escape")
	}
}

func TestUnixBitsSetgid(t *testing.T) {
	if UnixBits(os.ModeSetgid|0770) != 0o2770 {
		t.Fatalf("%04o", UnixBits(os.ModeSetgid|0770))
	}
	if UnixBits(02770) == 0o2770 {
		t.Fatal("Go FileMode(02770) must not be treated as Unix 02770")
	}
}
