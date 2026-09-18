// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
)

func TestPutCopiesFileAndDir(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	srcDir := t.TempDir()
	file := filepath.Join(srcDir, "key.pub")
	if err := os.WriteFile(file, []byte("ssh-ed25519 AAAA"), 0600); err != nil {
		t.Fatal(err)
	}
	kit := filepath.Join(srcDir, "kit")
	if err := os.Mkdir(kit, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kit, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(kit, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kit, "sub", "b.txt"), []byte("bb"), 0644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	args := append(cfgArgs, "-t", ".", file, kit)
	if code := putWith(u, &out, args); code != 0 {
		t.Fatalf("put: %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	want := []string{"key.pub", "kit/a.txt", "kit/sub/b.txt"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("stdout %q", out.String())
	}
	cubby := filepath.Join(env, "users", u.Name)
	got, err := os.ReadFile(filepath.Join(cubby, "key.pub"))
	if err != nil || string(got) != "ssh-ed25519 AAAA" {
		t.Fatalf("key.pub %q %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(cubby, "kit", "sub", "b.txt"))
	if err != nil || string(got) != "bb" {
		t.Fatalf("nested %q %v", got, err)
	}
	st, err := os.Stat(filepath.Join(cubby, "key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0660 {
		t.Fatalf("file mode %o", st.Mode().Perm())
	}
	for _, name := range []string{"kit", "kit/sub"} {
		dst, err := os.Stat(filepath.Join(cubby, name))
		if err != nil {
			t.Fatal(err)
		}
		if osutil.UnixBits(dst.Mode()) != 0o2770 {
			t.Fatalf("%s mode %04o", name, osutil.UnixBits(dst.Mode()))
		}
	}
}

func TestPutRenameAndDashT(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	srcDir := t.TempDir()
	a := filepath.Join(srcDir, "a.txt")
	b := filepath.Join(srcDir, "b.txt")
	if err := os.WriteFile(a, []byte("A"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("B"), 0644); err != nil {
		t.Fatal(err)
	}

	if code := putWith(u, ioDiscard(), append(cfgArgs, a, "renamed.txt")); code != 0 {
		t.Fatalf("rename: %d", code)
	}
	cubby := filepath.Join(env, "users", u.Name)
	got, err := os.ReadFile(filepath.Join(cubby, "renamed.txt"))
	if err != nil || string(got) != "A" {
		t.Fatalf("renamed %q %v", got, err)
	}

	if code := putWith(u, ioDiscard(), append(cfgArgs, "-t", "keys/", b)); code != 0 {
		t.Fatalf("-t: %d", code)
	}
	got, err = os.ReadFile(filepath.Join(cubby, "keys", "b.txt"))
	if err != nil || string(got) != "B" {
		t.Fatalf("keys %q %v", got, err)
	}
}

func TestPutAbsoluteDestUnderCubby(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	src := filepath.Join(t.TempDir(), "n")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	cubby := filepath.Join(env, "users", u.Name)
	dest := filepath.Join(cubby, "inside.txt")
	if code := putWith(u, ioDiscard(), append(cfgArgs, src, dest)); code != 0 {
		t.Fatalf("abs dest: %d", code)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "x" {
		t.Fatalf("inside %q %v", got, err)
	}
}

func TestPutRefusesEscapeAndSymlink(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	srcDir := t.TempDir()
	file := filepath.Join(srcDir, "ok")
	if err := os.WriteFile(file, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, file, "../outside")); code != 1 {
		t.Fatalf("escape dest: %d", code)
	}
	outside := filepath.Join(env, "outside")
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("wrote outside cubby: %v", err)
	}

	link := filepath.Join(srcDir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, link)); code != 1 {
		t.Fatalf("symlink: %d", code)
	}
}

func TestPutRefusesForeignCubbyAndMissing(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	src := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(src, []byte("f"), 0644); err != nil {
		t.Fatal(err)
	}
	other := u
	other.UID = u.UID + 1
	if code := putWith(other, ioDiscard(), append(cfgArgs, src)); code != 1 {
		t.Fatalf("foreign uid: %d", code)
	}

	missing := u
	missing.Name = "nobody-bootstash-test"
	if !pamauth.ValidUsername(missing.Name) {
		t.Fatal("fixture name")
	}
	if err := os.MkdirAll(filepath.Join(env, "users"), 0711); err != nil {
		t.Fatal(err)
	}
	if code := putWith(missing, ioDiscard(), append(cfgArgs, src)); code != 1 {
		t.Fatalf("missing cubby: %d", code)
	}
}

func TestPutRefusesRoot(t *testing.T) {
	prev := getuid
	t.Cleanup(func() { getuid = prev })
	getuid = func() int { return 0 }
	if _, err := lookupPutUser(); err == nil {
		t.Fatal("expected root refusal")
	}
}

func TestPutRefusesSelfCopy(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	cubby := filepath.Join(env, "users", u.Name)
	if err := os.WriteFile(filepath.Join(cubby, "x"), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, cubby, "nested")); code != 1 {
		t.Fatalf("self copy: %d", code)
	}
}

func TestPutUsage(t *testing.T) {
	u, _, cfgArgs := setupPutTest(t)
	if code := putWith(u, ioDiscard(), cfgArgs); code != 2 {
		t.Fatalf("no src: %d", code)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, "-t", "dir")); code != 2 {
		t.Fatalf("-t without src: %d", code)
	}
}

func TestPutOverwritesFile(t *testing.T) {
	u, env, cfgArgs := setupPutTest(t)
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "x")
	if err := os.WriteFile(src, []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, src)); code != 0 {
		t.Fatal(code)
	}
	if err := os.WriteFile(src, []byte("two"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, src)); code != 0 {
		t.Fatal(code)
	}
	got, err := os.ReadFile(filepath.Join(env, "users", u.Name, "x"))
	if err != nil || string(got) != "two" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestCubbyRel(t *testing.T) {
	cubby := "/var/lib/bootstash/users/alice"
	rel, err := cubbyRel(cubby, "")
	if err != nil || rel != "" {
		t.Fatalf("empty %q %v", rel, err)
	}
	rel, err = cubbyRel(cubby, filepath.Join(cubby, "keys", "id"))
	if err != nil || rel != "keys/id" {
		t.Fatalf("abs %q %v", rel, err)
	}
	if _, err := cubbyRel(cubby, "/tmp/nope"); err == nil {
		t.Fatal("outside")
	}
	if _, err := cubbyRel(cubby, "../bob"); err == nil {
		t.Fatal("dotdot")
	}
}

func ioDiscard() *bytes.Buffer {
	return &bytes.Buffer{}
}

func setupPutTest(t *testing.T) (putUser, string, []string) {
	t.Helper()
	cu, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !pamauth.ValidUsername(cu.Username) {
		t.Skip("current username is not a valid cubby name")
	}
	uid, err := strconv.Atoi(cu.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if uid == 0 {
		t.Skip("put refuses uid 0")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	users := filepath.Join(data, "users")
	cubby := filepath.Join(users, cu.Username)
	if err := os.MkdirAll(cubby, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0751); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(users, 0711); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(cubby, 0o2770); err != nil {
		t.Fatal(err)
	}
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(op, []byte("DATA="+data+"\nPUBLIC_URL=https://stash.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	u := putUser{Name: cu.Username, UID: uid}
	st, err := os.Lstat(cubby)
	if err != nil {
		t.Fatal(err)
	}
	gotUID, _, ok := osutil.FileIDs(st)
	if !ok || gotUID != uid {
		t.Fatalf("cubby uid %d want %d", gotUID, uid)
	}
	args := []string{"-defaults", filepath.Join(dir, "missing-dist"), "-config", op}
	return u, data, args
}
