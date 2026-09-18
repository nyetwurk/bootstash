// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package bind parses listen specifications and opens sockets.
package bind

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/nyet/bootstash/internal/osutil"
	"golang.org/x/sys/unix"
)

// Kind is the class of a bind spec.
type Kind int

const (
	// KindAny listens on wildcard addresses.
	KindAny Kind = iota
	// KindAddress listens on one IP.
	KindAddress
	// KindCIDR listens on local addresses in a prefix.
	KindCIDR
	// KindInterface listens on a NIC.
	KindInterface
	// KindUnix listens on a Unix socket.
	KindUnix
)

// Family restricts address family.
type Family int

const (
	// FamilyDual listens on IPv4 and IPv6 when applicable.
	FamilyDual Family = iota
	// FamilyIPv4 is IPv4 only.
	FamilyIPv4
	// FamilyIPv6 is IPv6 only.
	FamilyIPv6
)

// ErrNotReady means an interface is not present yet (retry).
var ErrNotReady = errors.New("bind target not ready")

// Spec is one BIND= line after parsing.
type Spec struct {
	Raw      string
	Kind     Kind
	Family   Family
	Port     int
	IP       net.IP
	Net      *net.IPNet
	Iface    string
	UnixPath string
}

// Target is a concrete listen address.
type Target struct {
	Network string
	Address string
	Device  string
	Unix    bool
}

// ParseSpec parses a single BIND value.
func ParseSpec(s string) (*Spec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty bind spec")
	}
	spec := &Spec{Raw: s, Family: FamilyDual}
	if strings.HasPrefix(s, "unix://") {
		path := strings.TrimPrefix(s, "unix://")
		if path == "" {
			return nil, fmt.Errorf("unix bind missing path")
		}
		spec.Kind = KindUnix
		spec.UnixPath = path
		return spec, nil
	}
	if strings.HasSuffix(s, "/ipv4") {
		spec.Family = FamilyIPv4
		s = strings.TrimSuffix(s, "/ipv4")
	} else if strings.HasSuffix(s, "/ipv6") {
		spec.Family = FamilyIPv6
		s = strings.TrimSuffix(s, "/ipv6")
	}

	host, portStr, err := splitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	spec.Port = port

	if host == "*" || host == "0.0.0.0" || host == "::" {
		spec.Kind = KindAny
		if host == "0.0.0.0" {
			spec.Family = FamilyIPv4
		}
		if host == "::" {
			spec.Family = FamilyIPv6
		}
		return spec, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		spec.Kind = KindAddress
		spec.IP = ip
		return spec, nil
	}
	if _, ipnet, err := net.ParseCIDR(host); err == nil {
		spec.Kind = KindCIDR
		spec.Net = ipnet
		return spec, nil
	}
	spec.Kind = KindInterface
	spec.Iface = host
	return spec, nil
}

func splitHostPort(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", fmt.Errorf("missing ] in %q", s)
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("missing port in %q", s)
		}
		return host, rest[1:], nil
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", fmt.Errorf("missing port in %q", s)
	}
	return s[:i], s[i+1:], nil
}

// Resolve turns a spec into listen targets using current addresses.
func (s *Spec) Resolve() ([]Target, error) {
	switch s.Kind {
	case KindUnix:
		return []Target{{Network: "unix", Address: s.UnixPath, Unix: true}}, nil
	case KindAny:
		return anyTargets(s.Port, s.Family), nil
	case KindAddress:
		if !familyOK(s.IP, s.Family) {
			return nil, fmt.Errorf("address %s does not match family", s.IP)
		}
		return []Target{{Network: ipNetwork(s.IP), Address: net.JoinHostPort(s.IP.String(), strconv.Itoa(s.Port))}}, nil
	case KindCIDR:
		return resolveCIDR(s)
	case KindInterface:
		return resolveIface(s)
	default:
		return nil, fmt.Errorf("unknown bind kind")
	}
}

func anyTargets(port int, fam Family) []Target {
	p := strconv.Itoa(port)
	var t []Target
	if fam != FamilyIPv6 {
		t = append(t, Target{Network: "tcp4", Address: net.JoinHostPort("0.0.0.0", p)})
	}
	if fam != FamilyIPv4 {
		t = append(t, Target{Network: "tcp6", Address: net.JoinHostPort("::", p)})
	}
	return t
}

func resolveCIDR(s *Spec) ([]Target, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	wantLoop := s.Net.IP.IsLoopback()
	wantLink := s.Net.IP.IsLinkLocalUnicast()
	var out []Target
	seen := map[string]bool{}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if ip == nil || ip.IsMulticast() {
			continue
		}
		if !s.Net.Contains(ip) {
			continue
		}
		if ip.IsLoopback() && !wantLoop {
			continue
		}
		if ip.IsLinkLocalUnicast() && !wantLink {
			continue
		}
		if !familyOK(ip, s.Family) {
			continue
		}
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(s.Port))
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, Target{Network: ipNetwork(ip), Address: addr})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no local addresses in %s", s.Net)
	}
	return out, nil
}

func resolveIface(s *Spec) ([]Target, error) {
	ifi, err := net.InterfaceByName(s.Iface)
	if err != nil {
		return nil, fmt.Errorf("%w: interface %s", ErrNotReady, s.Iface)
	}
	// Prefer SO_BINDTODEVICE on wildcard so new addresses are covered.
	p := strconv.Itoa(s.Port)
	var t []Target
	if s.Family != FamilyIPv6 {
		t = append(t, Target{Network: "tcp4", Address: net.JoinHostPort("0.0.0.0", p), Device: s.Iface})
	}
	if s.Family != FamilyIPv4 {
		t = append(t, Target{Network: "tcp6", Address: net.JoinHostPort("::", p), Device: s.Iface})
	}
	if ifi.Flags&net.FlagUp == 0 {
		return t, fmt.Errorf("%w: interface %s down", ErrNotReady, s.Iface)
	}
	return t, nil
}

// EnumerateIface is the fallback when SO_BINDTODEVICE is unavailable.
func EnumerateIface(name string, port int, fam Family) ([]Target, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("%w: interface %s", ErrNotReady, name)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var out []Target
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP == nil {
			continue
		}
		ip := ipn.IP
		if ip.IsMulticast() {
			continue
		}
		if !familyOK(ip, fam) {
			continue
		}
		host := ip.String()
		if ip.IsLinkLocalUnicast() && ip.To4() == nil {
			host = ip.String() + "%" + name
		}
		out = append(out, Target{Network: ipNetwork(ip), Address: net.JoinHostPort(host, strconv.Itoa(port))})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: interface %s has no addresses", ErrNotReady, name)
	}
	return out, nil
}

func familyOK(ip net.IP, fam Family) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4() != nil
	switch fam {
	case FamilyIPv4:
		return v4
	case FamilyIPv6:
		return !v4
	default:
		return true
	}
}

func ipNetwork(ip net.IP) string {
	if ip.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

// Listen opens a target. unix sockets are unlinked first.
func Listen(t Target, unixGroup string) (net.Listener, error) {
	if t.Unix {
		if err := os.Remove(t.Address); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		ln, err := net.Listen("unix", t.Address)
		if err != nil {
			return nil, err
		}
		if err := osutil.Chmod(t.Address, 0660); err != nil {
			ln.Close()
			return nil, err
		}
		if unixGroup != "" {
			if g, err := lookupGID(unixGroup); err == nil {
				_ = osutil.Chown(t.Address, -1, g)
			}
		}
		return ln, nil
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if t.Device != "" {
					if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, t.Device); err != nil {
						sockErr = err
					}
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
	ln, err := lc.Listen(nil, t.Network, t.Address)
	if err != nil && t.Device != "" {
		return nil, err
	}
	return ln, err
}

func lookupGID(name string) (int, error) {
	g, err := os.ReadFile("/etc/group")
	if err != nil {
		return -1, err
	}
	for _, line := range strings.Split(string(g), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[0] != name {
			continue
		}
		n, err := strconv.Atoi(parts[2])
		if err != nil {
			return -1, err
		}
		return n, nil
	}
	return -1, fmt.Errorf("group %s not found", name)
}
