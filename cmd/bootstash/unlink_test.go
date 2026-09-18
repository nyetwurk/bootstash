// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nyet/bootstash/internal/store"
)

func TestRunUnlinkDropsPAMMap(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(op, []byte("DATA="+data+"\nPUBLIC_URL=https://stash.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://accounts.google.com"
	if err := st.SetLink(iss, "sub-1", "alice"); err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateSession(iss, "sub-1", "a@b.c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess.PAMUser = "alice"
	if err := st.SaveSession(sess); err != nil {
		t.Fatal(err)
	}

	args := []string{"-defaults", filepath.Join(dir, "missing-dist"), "-config", op, "-secrets", filepath.Join(dir, "missing-secrets")}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	log.SetPrefix("bootstashd: ")
	log.SetFlags(log.Lmsgprefix)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetPrefix("")
		log.SetFlags(log.LstdFlags)
	})
	if code := runUnlink(append(args, "alice")); code != 0 {
		t.Fatalf("unlink alice: %d", code)
	}
	if !strings.Contains(logs.String(), "unlink pam=alice sub=sub-1") {
		t.Fatalf("missing unlink log: %q", logs.String())
	}
	if _, ok, err := st.LookupLink(iss, "sub-1"); err != nil || ok {
		t.Fatalf("link remains ok=%v err=%v", ok, err)
	}
	got, err := st.GetSession(sess.ID)
	if err != nil || got.PAMUser != "" {
		t.Fatalf("session %+v %v", got, err)
	}
	if code := runUnlink(append(args, "alice")); code != 1 {
		t.Fatalf("second unlink: %d", code)
	}
	if code := runUnlink(append(args, "../root")); code != 2 {
		t.Fatalf("bad user: %d", code)
	}
	if code := runUnlink(args); code != 2 {
		t.Fatalf("no user: %d", code)
	}
}
