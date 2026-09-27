// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
)

func TestMkdirRefusesNonRootAndPAMOff(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(filepath.Join(data, "users"), 0711); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Data: data, PAM: true, UnixGroup: "bootstash"}
	if err := mkdirUser(1, cfg, "alice"); err == nil {
		t.Fatal("non-root should fail")
	}
	if _, err := os.Stat(filepath.Join(data, "users", "alice")); !os.IsNotExist(err) {
		t.Fatal("non-root must not create a cubby")
	}
	cfg.PAM = false
	if err := mkdirUser(0, cfg, "alice"); err == nil {
		t.Fatal("PAM=no should fail")
	}
	if _, err := os.Stat(filepath.Join(data, "users", "alice")); !os.IsNotExist(err) {
		t.Fatal("PAM=no must not create a cubby")
	}
}

func TestMkdirRefusesRootAndUnknown(t *testing.T) {
	cfg := &config.Config{Data: t.TempDir(), PAM: true, UnixGroup: "bootstash"}
	if err := mkdirUser(0, cfg, "root"); err == nil {
		t.Fatal("root user should fail")
	}
	if err := mkdirUser(0, cfg, "no-such-bootstash-user"); err == nil {
		t.Fatal("unknown user should fail")
	}
	if err := mkdirUser(0, cfg, ".."); err == nil {
		t.Fatal("invalid name should fail")
	}
}

func TestMkdirCreatesAndRepeats(t *testing.T) {
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
	gid, err := strconv.Atoi(cu.Gid)
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(cu.Gid)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(t.TempDir(), "data")
	users := filepath.Join(data, "users")
	if err := os.MkdirAll(users, 0711); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Data: data, PAM: true, UnixGroup: g.Name}
	if err := mkdirUser(0, cfg, cu.Username); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(users, cu.Username)
	st, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetgid == 0 || st.Mode().Perm() != 0770 {
		t.Fatalf("want 02770, got %s", st.Mode())
	}
	owner, group, ok := osutil.FileIDs(st)
	if !ok || owner != uid || group != gid {
		t.Fatalf("owner %d:%d want %d:%d", owner, group, uid, gid)
	}
	if err := mkdirUser(0, cfg, cu.Username); err != nil {
		t.Fatal(err)
	}
}

func TestMkdirRefusesForeignOwner(t *testing.T) {
	cu, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cu.Username == "root" || !pamauth.ValidUsername("root") {
		t.Skip("need a linkable user other than the current one")
	}
	// root is not linkable. Use a second passwd name when one exists.
	other := otherLinkable(cu.Username)
	if other == "" {
		t.Skip("no second linkable passwd entry")
	}
	g, err := user.LookupGroupId(cu.Gid)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(t.TempDir(), "data")
	dir := filepath.Join(data, "users", other)
	if err := os.MkdirAll(dir, 0770); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Data: data, PAM: true, UnixGroup: g.Name}
	if err := mkdirUser(0, cfg, other); err == nil {
		t.Fatal("cubby owned by the test user must not be taken")
	}
	st, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, ok := osutil.FileIDs(st)
	uid, _ := strconv.Atoi(cu.Uid)
	if !ok || owner != uid {
		t.Fatalf("owner changed to %d", owner)
	}
}

func otherLinkable(self string) string {
	for _, name := range []string{"nobody", "daemon", "bin"} {
		if name == self {
			continue
		}
		acct, err := pamauth.Lookup(name)
		if err != nil || !pamauth.Linkable(acct) {
			continue
		}
		return acct.Name
	}
	return ""
}
