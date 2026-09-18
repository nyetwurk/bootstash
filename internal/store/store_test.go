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
	sess.PAMUser = "alice"
	if err := st.SaveSession(sess); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetSession(sess.ID)
	if err != nil || got.PAMUser != "alice" {
		t.Fatalf("%+v %v", got, err)
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
