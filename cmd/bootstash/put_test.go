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

	"github.com/nyet/bootstash/internal/config"
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
	args := append(cfgArgs, file, kit)
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

func TestPutSourcesAndDashT(t *testing.T) {
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

	if code := putWith(u, ioDiscard(), append(cfgArgs, a, b)); code != 0 {
		t.Fatalf("sources: %d", code)
	}
	cubby := filepath.Join(env, "users", u.Name)
	got, err := os.ReadFile(filepath.Join(cubby, "a.txt"))
	if err != nil || string(got) != "A" {
		t.Fatalf("a.txt %q %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(cubby, "b.txt"))
	if err != nil || string(got) != "B" {
		t.Fatalf("b.txt %q %v", got, err)
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
	dest := filepath.Join(cubby, "inside")
	if code := putWith(u, ioDiscard(), append(cfgArgs, "-t", dest, src)); code != 0 {
		t.Fatalf("abs -t: %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dest, "n"))
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
	if code := putWith(u, ioDiscard(), append(cfgArgs, "-t", "../outside", file)); code != 1 {
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
	if code := putWith(u, ioDiscard(), append(cfgArgs, cubby)); code != 1 {
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

func TestPutEmailCubby(t *testing.T) {
	u, data, cfgArgs := setupPutTest(t)
	home := filepath.Join(data, "home")
	if err := os.MkdirAll(home, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, os.ModeSetgid|os.ModeSticky|0773); err != nil {
		t.Fatal(err)
	}
	op := cfgArgs[3]
	body := "DATA=" + data + "\nREQUIRE_PAM_LINK=0\nALLOWED_EMAILS=Alice@Gmail.com\nALLOWED_EMAILS=bob@gmail.com\n"
	if err := os.WriteFile(op, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "client.ovpn")
	if err := os.WriteFile(src, []byte("client\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, src)); code == 0 {
		t.Fatal("two addresses without -email should fail")
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, "-email", "carol@gmail.com", src)); code == 0 {
		t.Fatal("unlisted email should fail")
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, "-email", "alice@gmail.com", src)); code != 0 {
		t.Fatal("put -email")
	}
	id, err := config.EmailCubbyID("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	cubby := filepath.Join(home, id)
	got, err := os.ReadFile(filepath.Join(cubby, "client.ovpn"))
	if err != nil || string(got) != "client\n" {
		t.Fatalf("file %q %v", got, err)
	}
	st, err := os.Lstat(cubby)
	if err != nil {
		t.Fatal(err)
	}
	uid, _, ok := osutil.FileIDs(st)
	if !ok || uid != u.UID {
		t.Fatalf("cubby uid %d want %d", uid, u.UID)
	}
	if osutil.UnixBits(st.Mode())&0o2770 != 0o2770 {
		t.Fatalf("cubby mode %04o", osutil.UnixBits(st.Mode()))
	}
	fst, err := os.Lstat(filepath.Join(cubby, "client.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	fuid, _, ok := osutil.FileIDs(fst)
	if !ok || fuid != u.UID {
		t.Fatalf("file uid %d want %d", fuid, u.UID)
	}
	bob, err := config.EmailCubbyID("bob@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(home, bob)); !os.IsNotExist(err) {
		t.Fatal("put created the other cubby")
	}
}

func TestPutEmailCubbySoleAddress(t *testing.T) {
	u, data, cfgArgs := setupPutTest(t)
	home := filepath.Join(data, "home")
	if err := os.MkdirAll(home, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, os.ModeSetgid|os.ModeSticky|0773); err != nil {
		t.Fatal(err)
	}
	op := cfgArgs[3]
	if err := os.WriteFile(op, []byte("DATA="+data+"\nREQUIRE_PAM_LINK=0\nALLOWED_EMAILS=only@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(src, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, src)); code != 0 {
		t.Fatal("sole address")
	}
	id, err := config.EmailCubbyID("only@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(home, id, "a.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestPutEmailCubbyNeedsHome(t *testing.T) {
	u, data, cfgArgs := setupPutTest(t)
	op := cfgArgs[3]
	if err := os.WriteFile(op, []byte("DATA="+data+"\nREQUIRE_PAM_LINK=0\nALLOWED_EMAILS=only@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(src, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, src)); code == 0 {
		t.Fatal("missing home/")
	}
	if err := os.MkdirAll(filepath.Join(data, "home"), 0555); err != nil {
		t.Fatal(err)
	}
	if code := putWith(u, ioDiscard(), append(cfgArgs, src)); code == 0 {
		t.Fatal("home not writable")
	}
}
