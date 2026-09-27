// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/oidcgoogle"
	"github.com/nyet/bootstash/internal/osutil"
)

type scriptIDP struct {
	id oidcgoogle.Identity
}

func (s scriptIDP) AuthCodeURL(_ context.Context, state, nonce, redirectURL string) (string, string, error) {
	return "https://accounts.google.com/o/oauth2/auth?state=" + state + "&nonce=" + nonce + "&redirect_uri=" + redirectURL, "verifier", nil
}

func (s scriptIDP) Exchange(_ context.Context, code, nonce, redirectURL, verifier string) (*oidcgoogle.Identity, error) {
	_ = code
	_ = nonce
	_ = redirectURL
	_ = verifier
	id := s.id
	return &id, nil
}

type seqIDP struct {
	ids []oidcgoogle.Identity
	n   int
}

func (s *seqIDP) AuthCodeURL(_ context.Context, state, nonce, redirectURL string) (string, string, error) {
	return "https://accounts.google.com/o/oauth2/auth?state=" + state + "&nonce=" + nonce + "&redirect_uri=" + redirectURL, "verifier", nil
}

func (s *seqIDP) Exchange(_ context.Context, code, nonce, redirectURL, verifier string) (*oidcgoogle.Identity, error) {
	_ = code
	_ = nonce
	_ = redirectURL
	_ = verifier
	if s.n >= len(s.ids) {
		return nil, os.ErrNotExist
	}
	id := s.ids[s.n]
	s.n++
	return &id, nil
}

func emailIdentity(email, sub string, verified bool) oidcgoogle.Identity {
	return oidcgoogle.Identity{
		Issuer:        "https://accounts.google.com",
		Subject:       sub,
		Email:         email,
		EmailVerified: verified,
	}
}

func newScriptServer(t *testing.T, dir string, idp IDP, emails []string, requirePAM bool) *Server {
	t.Helper()
	cfg := testConfig(dir)
	cfg.AllowedEmails = emails
	cfg.RequirePAMLink = requirePAM
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, st, idp, mapPAM{"alice": "secret"}, bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHomeDirMode(t *testing.T) {
	_, _, dir := testServer(t)
	st, err := os.Stat(filepath.Join(dir, "home"))
	if err != nil {
		t.Fatal(err)
	}
	if osutil.UnixBits(st.Mode()) != 0o3773 {
		t.Fatalf("home mode %04o", osutil.UnixBits(st.Mode()))
	}
}

func TestCallbackAllowlist(t *testing.T) {
	dir := t.TempDir()
	s := newScriptServer(t, dir, scriptIDP{id: emailIdentity("bob@gmail.com", "sub-bob", true)}, []string{"alice@gmail.com"}, true)
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unlisted: %d %s", rr.Code, rr.Body.String())
	}
	if cookieNamed(rr, s.cookieName()) != nil {
		t.Fatal("unlisted session cookie")
	}
	if loc := rr.Header().Get("Location"); loc == "/link" {
		t.Fatal("unlisted reached /link")
	}

	dir = t.TempDir()
	s = newScriptServer(t, dir, scriptIDP{id: emailIdentity("alice@gmail.com", "sub-a", false)}, []string{"alice@gmail.com"}, true)
	state, tx = googleLogin(t, s)
	rr = do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusForbidden || cookieNamed(rr, s.cookieName()) != nil {
		t.Fatalf("unverified: %d cookie %v", rr.Code, cookieNamed(rr, s.cookieName()))
	}

	dir = t.TempDir()
	seq := &seqIDP{ids: []oidcgoogle.Identity{
		emailIdentity("Alice@Gmail.com", "sub-a", true),
		emailIdentity("alice@gmail.com", "sub-a", true),
		emailIdentity("alice@gmail.com", "sub-other", true),
	}}
	s = newScriptServer(t, dir, seq, []string{"alice@gmail.com"}, false)
	state, tx = googleLogin(t, s)
	rr = do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("first: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	if cookieNamed(rr, s.cookieName()) == nil {
		t.Fatal("first cookie")
	}
	state, tx = googleLogin(t, s)
	rr = do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("same sub: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	state, tx = googleLogin(t, s)
	rr = do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusForbidden || cookieNamed(rr, s.cookieName()) != nil {
		t.Fatalf("other sub: %d", rr.Code)
	}
}

func TestCallbackEmptyListStillLinks(t *testing.T) {
	s, _, _ := testServer(t)
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/link" {
		t.Fatalf("admit-all: %d %s", rr.Code, rr.Header().Get("Location"))
	}
}

func TestTwoEmailCubbies(t *testing.T) {
	dir := t.TempDir()
	seq := &seqIDP{ids: []oidcgoogle.Identity{
		emailIdentity("alice@gmail.com", "sub-a", true),
		emailIdentity("bob@gmail.com", "sub-b", true),
	}}
	s := newScriptServer(t, dir, seq, []string{"alice@gmail.com", "bob@gmail.com"}, false)
	aliceID, err := config.EmailCubbyID("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := config.EmailCubbyID("bob@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "home", aliceID), 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "home", bobID), 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "home", aliceID, "a.txt"), []byte("alice"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "home", bobID, "b.txt"), []byte("bob"), 0660); err != nil {
		t.Fatal(err)
	}
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	aliceC := cookieNamed(rr, s.cookieName())
	if aliceC == nil || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("alice login %d", rr.Code)
	}
	state, tx = googleLogin(t, s)
	rr = do(s, oauthCallback(state, tx))
	bobC := cookieNamed(rr, s.cookieName())
	if bobC == nil {
		t.Fatal("bob cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/home/a.txt", nil)
	req.AddCookie(aliceC)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "alice" {
		t.Fatalf("alice read: %d %s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/home/b.txt", nil)
	req.AddCookie(aliceC)
	rr = do(s, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("alice saw bob: %s", rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/home/b.txt", nil)
	req.AddCookie(bobC)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "bob" {
		t.Fatalf("bob read: %d %s", rr.Code, rr.Body.String())
	}
}

func TestLinkedSessionIgnoresEmailCubby(t *testing.T) {
	dir := t.TempDir()
	s := newScriptServer(t, dir, scriptIDP{id: emailIdentity("alice@gmail.com", "sub-a", true)}, []string{"alice@gmail.com"}, false)
	if err := s.store.SetLink("https://accounts.google.com", "sub-a", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "users", "alice"), 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "pam.txt"), []byte("pam"), 0660); err != nil {
		t.Fatal(err)
	}
	id, err := config.EmailCubbyID("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "home", id), 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "home", id, "mail.txt"), []byte("mail"), 0660); err != nil {
		t.Fatal(err)
	}
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	c := cookieNamed(rr, s.cookieName())
	if c == nil || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("login %d %s", rr.Code, rr.Header().Get("Location"))
	}
	req := httptest.NewRequest(http.MethodGet, "/home/pam.txt", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "pam" {
		t.Fatalf("pam cubby: %d %s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/home/mail.txt", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code == http.StatusOK {
		t.Fatal("linked session opened the email cubby")
	}
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "alice@gmail.com · alice") {
		t.Fatalf("linked header: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Not linked yet") {
		t.Fatal("linked header says not linked")
	}
}

func TestEmailCubbyHeaderOmitsLinkPrompt(t *testing.T) {
	dir := t.TempDir()
	s := newScriptServer(t, dir, scriptIDP{id: emailIdentity("alice@gmail.com", "sub-a", true)}, []string{"alice@gmail.com"}, false)
	id, err := config.EmailCubbyID("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "home", id), 0770); err != nil {
		t.Fatal(err)
	}
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	c := cookieNamed(rr, s.cookieName())
	if c == nil {
		t.Fatal("cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr = do(s, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, "alice@gmail.com") {
		t.Fatalf("header: %d %s", rr.Code, body)
	}
	if strings.Contains(body, "Not linked yet") {
		t.Fatalf("email cubby header: %s", body)
	}
}

func TestEmailCubbyOpenVPN(t *testing.T) {
	dir := t.TempDir()
	s := newScriptServer(t, dir, scriptIDP{id: emailIdentity("alice@gmail.com", "sub-a", true)}, []string{"alice@gmail.com"}, false)
	id, err := config.EmailCubbyID("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	cubby := filepath.Join(dir, "home", id)
	if err := os.MkdirAll(cubby, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cubby, "client.ovpn"), []byte("client\n"), 0640); err != nil {
		t.Fatal(err)
	}
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	c := cookieNamed(rr, s.cookieName())
	if c == nil {
		t.Fatal("cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?download=1", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != ovpnProfileType {
		t.Fatalf("profile: %d %s %s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	if rr.Body.String() == "" {
		t.Fatal("empty profile")
	}
}

func TestEmailCubbyKeepsOwner(t *testing.T) {
	dir := t.TempDir()
	id, err := config.EmailCubbyID("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	cubby := filepath.Join(dir, "home", id)
	if err := os.MkdirAll(cubby, 0700); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(cubby)
	if err != nil {
		t.Fatal(err)
	}
	uid, _, ok := osutil.FileIDs(st)
	if !ok {
		t.Fatal("uid")
	}
	s := newScriptServer(t, dir, scriptIDP{id: emailIdentity("alice@gmail.com", "sub-a", true)}, []string{"alice@gmail.com"}, false)
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	c := cookieNamed(rr, s.cookieName())
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	_ = do(s, req)
	st, err = os.Lstat(cubby)
	if err != nil {
		t.Fatal(err)
	}
	got, _, ok := osutil.FileIDs(st)
	if !ok || got != uid {
		t.Fatalf("uid %d want %d", got, uid)
	}
	if osutil.UnixBits(st.Mode())&0o2770 != 0o2770 {
		t.Fatalf("mode %04o", osutil.UnixBits(st.Mode()))
	}
	cu, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	want, err := strconv.Atoi(cu.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if uid != want {
		t.Fatalf("creator uid %d current %d", uid, want)
	}
}
