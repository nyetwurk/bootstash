// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/nyet/bootstash/internal/jail"
)

func TestFormatSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1 MiB"},
		{1572864, "1.5 MiB"},
	}
	for _, c := range cases {
		if got := formatSize(c.n); got != c.want {
			t.Errorf("formatSize(%d)=%q want %q", c.n, got, c.want)
		}
	}
}

func TestFormatDateUTC(t *testing.T) {
	ts := time.Date(2026, 9, 17, 15, 4, 0, 0, time.UTC)
	if got := formatDate(ts); got != "2026-09-17 15:04" {
		t.Fatalf("formatDate=%q", got)
	}
}

func TestDownloadNameIn(t *testing.T) {
	cases := []struct {
		listing, file, want string
	}{
		{"", "a.txt", "a.txt"},
		{"kit", "kit/a.txt", "a.txt"},
		{"", "kit/a.txt", ""},
		{"kit", "a.txt", ""},
		{"kit", "kit/sub/a.txt", ""},
	}
	for _, c := range cases {
		if got := downloadNameIn(c.listing, c.file); got != c.want {
			t.Errorf("downloadNameIn(%q,%q)=%q want %q", c.listing, c.file, got, c.want)
		}
	}
}

func TestJailErrKey(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{jail.ErrEscape, "not-allowed"},
		{fmt.Errorf("%w: too many", jail.ErrEscape), "not-allowed"},
		{syscall.EACCES, "denied"},
		{os.ErrNotExist, "missing"},
		{jail.ErrNotDir, "not-a-folder"},
		{syscall.ENOTDIR, "not-a-folder"},
		{errors.New("io"), "failed"},
	}
	for _, c := range cases {
		if got := jailErrKey(c.err); got != c.want {
			t.Errorf("jailErrKey(%v)=%q want %q", c.err, got, c.want)
		}
	}
	if listingErrMessage("failed") != "Could not open that." {
		t.Fatalf("failed message %q", listingErrMessage("failed"))
	}
}
