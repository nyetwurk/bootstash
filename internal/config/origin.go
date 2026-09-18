// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nyet/bootstash/internal/bind"
)

// defaultCertRoot is where the Let's Encrypt deploy hook copies PEMs.
// The daemon (User=bootstash) cannot read /etc/letsencrypt/live.
const defaultCertRoot = "/etc/bootstash/certs"

// certRoot is defaultCertRoot. Tests replace it.
var certRoot = defaultCertRoot

// lookupFQDN is hostname -f. Tests replace it.
var lookupFQDN = hostnameFQDN

func hostnameFQDN() (string, error) {
	out, err := exec.Command("hostname", "-f").Output()
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(string(out))
	if host == "" || strings.ContainsAny(host, "/:\\ \t\n") {
		return "", fmt.Errorf("hostname -f is not a host")
	}
	return host, nil
}

func usableOriginHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "localhost.localdomain", "localhost.local", "ip6-localhost":
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return host != ""
}

func originHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func firstTCPPort(binds []string) int {
	for _, raw := range binds {
		spec, err := bind.ParseSpec(raw)
		if err != nil || spec.Kind == bind.KindUnix {
			continue
		}
		return spec.Port
	}
	return 0
}

func originName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func regularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func certPair(host string) (string, string, bool) {
	if !usableOriginHost(host) {
		return "", "", false
	}
	cert := filepath.Join(certRoot, host, "fullchain.pem")
	key := filepath.Join(certRoot, host, "privkey.pem")
	if !regularFile(cert) || !regularFile(key) {
		return "", "", false
	}
	return cert, key, true
}

func onlyCertDir() string {
	ents, err := os.ReadDir(certRoot)
	if err != nil {
		return ""
	}
	name := ""
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if _, _, ok := certPair(e.Name()); !ok {
			continue
		}
		if name != "" {
			return ""
		}
		name = e.Name()
	}
	return name
}

func fqdn() string {
	h, err := lookupFQDN()
	if err != nil {
		return ""
	}
	return h
}

// deriveCertName fills CertName when unset: dest that matches
// hostname -f, else the only certs/<name>/ pair (hook chose it).
func (c *Config) deriveCertName() {
	if strings.TrimSpace(c.CertName) != "" {
		return
	}
	if h := fqdn(); h != "" {
		if _, _, ok := certPair(h); ok {
			c.CertName = h
			return
		}
	}
	c.CertName = onlyCertDir()
}

func (c *Config) deriveTLSFiles() {
	if strings.TrimSpace(c.TLSCert) != "" || strings.TrimSpace(c.TLSKey) != "" {
		return
	}
	for _, h := range []string{c.CertName, originName(c.PublicURL), fqdn()} {
		if cert, key, ok := certPair(h); ok {
			c.TLSCert, c.TLSKey = cert, key
			return
		}
	}
}

func (c *Config) derivePublicURL() {
	if strings.TrimSpace(c.PublicURL) != "" {
		return
	}
	host := c.CertName
	if host == "" {
		host = fqdn()
	}
	port := firstTCPPort(c.Binds)
	if !usableOriginHost(host) || port == 0 {
		return
	}
	scheme := "http"
	if c.TLSCert != "" && c.TLSKey != "" {
		scheme = "https"
	}
	h := originHost(host)
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		c.PublicURL = scheme + "://" + h
		return
	}
	c.PublicURL = fmt.Sprintf("%s://%s:%d", scheme, h, port)
}
