// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nyet/bootstash/internal/osutil"
)

func TestSessionAndLink(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateSession("https://accounts.google.com", "sub-1", "a@b.c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSession(sess.ID)
	if err != nil || got.Sub != "sub-1" || got.PAMUser != "" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := st.SetLink(sess.Iss, sess.Sub, "alice"); err != nil {
		t.Fatal(err)
	}
	pam, ok, err := st.LookupLink(sess.Iss, sess.Sub)
	if err != nil || !ok || pam != "alice" {
		t.Fatalf("%s %v %v", pam, ok, err)
	}
	users, err := st.LinkedPAMUsers()
	if err != nil || len(users) != 1 || users[0] != "alice" {
		t.Fatalf("%v %v", users, err)
	}
	links, err := st.ListLinks()
	if err != nil || len(links) != 1 || links[0].PAMUser != "alice" || links[0].Subject != "sub-1" {
		t.Fatalf("%+v %v", links, err)
	}
	sess.PAMUser = "alice"
	if err := st.SaveSession(sess); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetSession(sess.ID)
	if err != nil || got.PAMUser != "alice" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := st.DeleteSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(sess.ID); !os.IsNotExist(err) {
		t.Fatalf("deleted session: %v", err)
	}
	if err := st.DeleteSession(sess.ID); err != nil {
		t.Fatal(err)
	}
}

func TestUnlinkPAMDropsLinksAndSessions(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://accounts.google.com"
	if err := st.SetLink(iss, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLink(iss, "sub-2", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLink(iss, "sub-bob", "bob"); err != nil {
		t.Fatal(err)
	}
	alice, err := st.CreateSession(iss, "sub-1", "a@b.c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	alice.PAMUser = "alice"
	if err := st.SaveSession(alice); err != nil {
		t.Fatal(err)
	}
	bob, err := st.CreateSession(iss, "sub-bob", "b@b.c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bob.PAMUser = "bob"
	if err := st.SaveSession(bob); err != nil {
		t.Fatal(err)
	}

	removed, n, err := st.UnlinkPAM("alice")
	if err != nil || n != 1 || len(removed) != 2 {
		t.Fatalf("removed=%d sessions=%d err=%v", len(removed), n, err)
	}
	if _, ok, err := st.LookupLink(iss, "sub-1"); err != nil || ok {
		t.Fatalf("alice link remains ok=%v err=%v", ok, err)
	}
	if pam, ok, err := st.LookupLink(iss, "sub-bob"); err != nil || !ok || pam != "bob" {
		t.Fatalf("bob link pam=%s ok=%v err=%v", pam, ok, err)
	}
	got, err := st.GetSession(alice.ID)
	if err != nil || got.PAMUser != "" {
		t.Fatalf("alice session %+v %v", got, err)
	}
	got, err = st.GetSession(bob.ID)
	if err != nil || got.PAMUser != "bob" {
		t.Fatalf("bob session %+v %v", got, err)
	}

	removed, n, err = st.UnlinkPAM("alice")
	if err != nil || n != 0 || len(removed) != 0 {
		t.Fatalf("second unlink removed=%d sessions=%d err=%v", len(removed), n, err)
	}
}

func TestGetSessionRejectsUnsafeID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../x", "..", "zz", "sessions-x.json"} {
		if _, err := st.GetSession(id); !os.IsNotExist(err) {
			t.Fatalf("%q: %v", id, err)
		}
	}
}

func TestBadPasswordDoesNotWriteLink(t *testing.T) {
	// Mapping is only written by SetLink; this documents the store stays empty
	// unless the caller invokes SetLink after a successful PAM check.
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := st.LookupLink("iss", "sub")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestStateFilesMatchDirOwner(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetLink("https://accounts.google.com", "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	dirSt, err := os.Stat(st.Dir())
	if err != nil {
		t.Fatal(err)
	}
	fileSt, err := os.Stat(filepath.Join(st.Dir(), "links.json"))
	if err != nil {
		t.Fatal(err)
	}
	du, dg, ok := osutil.FileIDs(dirSt)
	if !ok {
		t.Fatal("dir ids")
	}
	fu, fg, ok := osutil.FileIDs(fileSt)
	if !ok {
		t.Fatal("file ids")
	}
	if fu != du || fg != dg {
		t.Fatalf("links.json %d:%d dir %d:%d", fu, fg, du, dg)
	}
	if got := fileSt.Mode().Perm(); got != 0600 {
		t.Fatalf("links.json mode %04o", got)
	}
}

func TestEnsureCryptoKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k1, err := st.EnsureCryptoKey(nil)
	if err != nil || len(k1) < 32 {
		t.Fatal(err)
	}
	k2, err := st.EnsureCryptoKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("key should persist")
	}
}

func TestTwoStoresSeeEachOthersLinks(t *testing.T) {
	dir := t.TempDir()
	st1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://accounts.google.com"
	if err := st1.SetLink(iss, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	pam, ok, err := st2.LookupLink(iss, "sub-1")
	if err != nil || !ok || pam != "alice" {
		t.Fatalf("st2 pam=%s ok=%v err=%v", pam, ok, err)
	}
	sess, err := st1.CreateSession(iss, "sub-1", "a@b.c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess.PAMUser = "alice"
	if err := st1.SaveSession(sess); err != nil {
		t.Fatal(err)
	}
	removed, n, err := st2.UnlinkPAM("alice")
	if err != nil || n != 1 || len(removed) != 1 {
		t.Fatalf("unlink removed=%d sessions=%d err=%v", len(removed), n, err)
	}
	if _, ok, err := st1.LookupLink(iss, "sub-1"); err != nil || ok {
		t.Fatalf("st1 still linked ok=%v err=%v", ok, err)
	}
	got, err := st1.GetSession(sess.ID)
	if err != nil || got.PAMUser != "" {
		t.Fatalf("session %+v %v", got, err)
	}
}

func TestCreateSessionUnlinkRace(t *testing.T) {
	dir := t.TempDir()
	st1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://accounts.google.com"
	if err := st1.SetLink(iss, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = st1.CreateSession(iss, "sub-1", "a@b.c", time.Hour)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, _, _ = st2.UnlinkPAM("alice")
	}()
	close(start)
	wg.Wait()
	if _, linked, err := st1.LookupLink(iss, "sub-1"); err != nil || linked {
		t.Fatalf("link remains linked=%v err=%v", linked, err)
	}
	ents, err := os.ReadDir(st1.Dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		name := e.Name()
		if len(name) < 14 || name[:9] != "sessions-" || name[len(name)-5:] != ".json" {
			continue
		}
		got, err := st1.GetSession(name[9 : len(name)-5])
		if err != nil {
			continue
		}
		if got.PAMUser == "alice" {
			t.Fatalf("session %s still pam=alice after unlink", got.ID)
		}
	}
}
