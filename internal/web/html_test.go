// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"os"
	"strings"
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

func TestPickOvpn(t *testing.T) {
	if pickOvpn(nil) != "" {
		t.Fatal("empty")
	}
	if pickOvpn([]string{"a.ovpn"}) != "a.ovpn" {
		t.Fatal("one")
	}
	if pickOvpn([]string{"a.ovpn", "client.ovpn"}) != "client.ovpn" {
		t.Fatal("prefer client.ovpn")
	}
	if pickOvpn([]string{"kit/a.ovpn", "kit/b.ovpn"}) != "" {
		t.Fatal("several without client.ovpn")
	}
	if pickOvpn([]string{"kit/client.ovpn", "a.ovpn"}) != "kit/client.ovpn" {
		t.Fatal("one nested client.ovpn")
	}
	if pickOvpn([]string{"client.ovpn", "kit/client.ovpn"}) != "" {
		t.Fatal("several client.ovpn")
	}
}

func TestOvpnDisplayName(t *testing.T) {
	if ovpnDisplayName("nyet-tcp.ovpn", nil) != "nyet-tcp" {
		t.Fatal("no remote")
	}
	if ovpnDisplayName("kit/a.ovpn", nil) != "kit/a" {
		t.Fatal("nested")
	}
	if ovpnDisplayName("nyet-tcp.ovpn", []byte("client\nremote vpn.example 1194 udp\n")) != "vpn.example [nyet-tcp]" {
		t.Fatal("remote [file]")
	}
	if ovpnDisplayName("host.ovpn", []byte("remote host\n")) != "host" {
		t.Fatal("same as remote")
	}
	got := string(ovpnTitledProfile("nyet-tcp.ovpn", []byte("remote vpn.example\n")))
	if !strings.Contains(got, `setenv FRIENDLY_NAME "vpn.example [nyet-tcp]"`) || !strings.Contains(got, "remote vpn.example") {
		t.Fatalf("titled %q", got)
	}
	keep := []byte("# OVPN_ACCESS_SERVER_FRIENDLY_NAME=mine\nremote vpn.example\n")
	if string(ovpnTitledProfile("nyet-tcp.ovpn", keep)) != string(keep) {
		t.Fatal("leave existing title")
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
	if listingErrMessage("too-large") != "That file is too large." {
		t.Fatalf("too-large message %q", listingErrMessage("too-large"))
	}
}
