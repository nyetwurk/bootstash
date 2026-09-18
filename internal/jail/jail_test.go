// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package jail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectDotDot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("no"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Open("../" + filepath.Base(outside) + "/secret"); err == nil {
		t.Fatal("expected escape")
	}
	if _, err := j.Open(".."); err == nil {
		t.Fatal("expected escape")
	}
	if _, err := j.Open("foo/../../etc/passwd"); err == nil {
		t.Fatal("expected escape")
	}
}

func TestExtraSlashes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("//a///b.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
}

func TestFileNameIsLocal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Name() != "ok.txt" {
		t.Fatalf("name %q", f.Name())
	}
}

func TestSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("no"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(root, "up")); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Open("escape"); err == nil {
		t.Fatal("absolute symlink should fail")
	}
	if _, err := j.Open("up"); err == nil {
		t.Fatal(".. symlink should fail")
	}
}

func TestInternalSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "hello.txt"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("b/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2)
	n, err := f.Read(buf)
	if err != nil || n != 2 || string(buf) != "hi" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}

func TestNUL(t *testing.T) {
	root := t.TempDir()
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Open("foo\x00bar"); err == nil {
		t.Fatal("expected invalid")
	}
}

func TestCreateAndMkdir(t *testing.T) {
	root := t.TempDir()
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Mkdir("sub", 0770); err != nil {
		t.Fatal(err)
	}
	f, err := j.Create("sub/file.txt", 0660)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := j.Create("../nope", 0660); err == nil {
		t.Fatal("create escape")
	}
}

func TestRemoveFileAndEmptyDir(t *testing.T) {
	root := t.TempDir()
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Mkdir("sub", 0770); err != nil {
		t.Fatal(err)
	}
	f, err := j.Create("sub/file.txt", 0660)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := j.Remove("sub"); err != ErrNotEmpty {
		t.Fatalf("expected not empty, got %v", err)
	}
	if err := j.Remove("sub/file.txt"); err != nil {
		t.Fatal(err)
	}
	if err := j.Remove("sub"); err != nil {
		t.Fatal(err)
	}
	if err := j.Remove(""); err == nil {
		t.Fatal("removed jail root")
	}
	if err := j.Remove("../nope"); err == nil {
		t.Fatal("remove escape")
	}
}

func TestRemoveSymlinkDoesNotFollow(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Remove("escape"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatal("followed symlink and removed outside file")
	}
}
