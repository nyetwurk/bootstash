// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"os"
	"testing"
	"time"
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
