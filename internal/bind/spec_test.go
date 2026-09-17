// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package bind

import (
	"strings"
	"testing"
)

func TestParseSpecs(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
		port int
	}{
		{"*:8443", KindAny, 8443},
		{"0.0.0.0:8443", KindAny, 8443},
		{"[::]:8443", KindAny, 8443},
		{"127.0.0.1:8080", KindAddress, 8080},
		{"[::1]:8080", KindAddress, 8080},
		{"192.168.1.0/24:8443", KindCIDR, 8443},
		{"10.0.0.0/8:8080", KindCIDR, 8080},
		{"2001:db8::/64:8443", KindCIDR, 8443},
		{"eth0:8443", KindInterface, 8443},
		{"wg0:8443/ipv4", KindInterface, 8443},
		{"unix:///run/bootstash.sock", KindUnix, 0},
	}
	for _, tc := range cases {
		sp, err := ParseSpec(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if sp.Kind != tc.kind || sp.Port != tc.port {
			t.Fatalf("%s: kind=%d port=%d", tc.in, sp.Kind, sp.Port)
		}
	}
	if _, err := ParseSpec("127.0.0.1:0"); err == nil {
		t.Fatal("port 0 should fail")
	}
}

func TestParseFamily(t *testing.T) {
	sp, err := ParseSpec("eth0:8443/ipv6")
	if err != nil {
		t.Fatal(err)
	}
	if sp.Family != FamilyIPv6 || sp.Iface != "eth0" {
		t.Fatalf("%+v", sp)
	}
}

func TestResolveLoopbackAddress(t *testing.T) {
	sp, err := ParseSpec("127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := sp.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || !strings.HasPrefix(ts[0].Address, "127.0.0.1:") {
		t.Fatalf("%#v", ts)
	}
}

func TestCIDRLoopback(t *testing.T) {
	sp, err := ParseSpec("127.0.0.1/32:18081")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := sp.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 {
		t.Fatalf("expected 127.0.0.1 got %#v", ts)
	}
}
