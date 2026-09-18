// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package bind

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestListenLoopbackAndUnix(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	m := NewManager(handler, "", nil)
	defer m.Close(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	sock := filepath.Join(t.TempDir(), "bootstash.sock")
	specs := []Spec{}
	for _, raw := range []string{
		"127.0.0.1:" + strconv.Itoa(port),
		"unix://" + sock,
	} {
		sp, err := ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, *sp)
	}
	if err := m.Sync(specs, false, false); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("got %q", b)
	}
	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}
	resp, err = c.Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("unix got %q", b)
	}
}

func TestHTTPSReloadCert(t *testing.T) {
	dir := t.TempDir()
	cert1, key1 := writeTestCert(t, dir, "one")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	var holder tls.Certificate
	c, err := tls.LoadX509KeyPair(cert1, key1)
	if err != nil {
		t.Fatal(err)
	}
	holder = c
	m := NewManager(handler, "", func() (*tls.Certificate, error) { return &holder, nil })
	defer m.Close(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	sp, err := ParseSpec("127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync([]Spec{*sp}, true, false); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cert2, key2 := writeTestCert(t, dir, "two")
	c2, err := tls.LoadX509KeyPair(cert2, key2)
	if err != nil {
		t.Fatal(err)
	}
	holder = c2
	resp, err = client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(bad, key2); err == nil {
		t.Fatal("expected bad pair to fail")
	}
	// previous holder remains
	resp, err = client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestHTTPSThenHTTP(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir, "one")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(handler, "", func() (*tls.Certificate, error) { return &c, nil })
	defer m.Close(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	sp, err := ParseSpec("127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync([]Spec{*sp}, true, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync([]Spec{*sp}, false, true); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func writeTestCert(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, cn+".crt")
	keyPath := filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
