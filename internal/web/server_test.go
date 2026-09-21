// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/oidcgoogle"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
)

type fakeIDP struct{}

func (fakeIDP) AuthCodeURL(_ context.Context, state, nonce, redirectURL string) (string, string, error) {
	return "https://accounts.google.com/o/oauth2/auth?state=" + state + "&nonce=" + nonce + "&redirect_uri=" + redirectURL, "verifier", nil
}

func (fakeIDP) Exchange(_ context.Context, code, nonce, redirectURL, verifier string) (*oidcgoogle.Identity, error) {
	_ = nonce
	_ = redirectURL
	_ = verifier
	return &oidcgoogle.Identity{
		Issuer:  "https://accounts.google.com",
		Subject: "sub-" + code,
		Email:   "alice@example.com",
	}, nil
}

type mapPAM map[string]string

func (m mapPAM) Authenticate(username, password string) error {
	if m[username] == password && password != "" {
		return nil
	}
	return pamauth.ErrDenied
}

func testConfig(dir string) *config.Config {
	return &config.Config{
		PublicURL:          "https://stash.test",
		Binds:              []string{"127.0.0.1:0"},
		Data:               dir,
		GoogleClientID:     "cid",
		GoogleClientSecret: "secret",
		PAMService:         "bootstashd",
		MaxUpload:          64,
		UnixGroup:          "bootstash",
	}
}

func newTestServer(t *testing.T, dir string, pam mapPAM) (*Server, *store.Store) {
	t.Helper()
	if pam == nil {
		pam = mapPAM{"alice": "secret"}
	}
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(testConfig(dir), st, fakeIDP{}, pam, bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

func testServer(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, st := newTestServer(t, dir, nil)
	return s, st, dir
}

func TestEnsureUserDirRejectsTraversal(t *testing.T) {
	s, _, dir := testServer(t)
	if err := s.ensureUserDir("../etc"); err == nil {
		t.Fatal("expected reject")
	}
	if err := s.ensureUserDir("alice/../etc"); err == nil {
		t.Fatal("expected reject")
	}
	if _, err := os.Stat(filepath.Join(dir, "etc")); err == nil {
		t.Fatal("must not create outside users/")
	}
}

func TestUsersDirTraversable(t *testing.T) {
	_, _, dir := testServer(t)
	st, err := os.Stat(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0711 {
		t.Fatalf("users mode %04o", got)
	}
}

func TestFixCubbiesSetsSetgidOnStart(t *testing.T) {
	dir := t.TempDir()
	cubby := filepath.Join(dir, "users", "alice")
	if err := os.MkdirAll(cubby, 0770); err != nil {
		t.Fatal(err)
	}
	newTestServer(t, dir, nil)
	info, err := os.Stat(cubby)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("cubby mode %s", info.Mode())
	}
}

func TestFixCubbiesGroupReadNotOther(t *testing.T) {
	dir := t.TempDir()
	cubby := filepath.Join(dir, "users", "alice")
	if err := os.MkdirAll(cubby, 0770); err != nil {
		t.Fatal(err)
	}
	odd := filepath.Join(cubby, "only-other.txt")
	ok644 := filepath.Join(cubby, "world.txt")
	priv := filepath.Join(cubby, "private.txt")
	if err := os.WriteFile(odd, []byte("x"), 0604); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(odd, 0604); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ok644, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ok644, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priv, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(priv, 0600); err != nil {
		t.Fatal(err)
	}
	newTestServer(t, dir, nil)
	got := func(p string) os.FileMode {
		t.Helper()
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}
	if g := got(odd); g != 0640 {
		t.Fatalf("odd %04o", g)
	}
	if g := got(ok644); g != 0640 {
		t.Fatalf("0644 became %04o", g)
	}
	if g := got(priv); g != 0640 {
		t.Fatalf("0600 became %04o", g)
	}
}

func TestHomeGetFixesCopiedFile(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	p := filepath.Join(dir, "users", "alice", "copied.bin")
	if err := os.WriteFile(p, []byte("stash"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/copied.bin", nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "stash" {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("after get %04o", info.Mode().Perm())
	}
}

func OpenStore(dir string) (*store.Store, error) {
	return store.Open(dir)
}

func linkedSession(t *testing.T, s *Server, st *store.Store, pamUser string) *http.Cookie {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(s.config().Data, "users", pamUser), 0770); err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateSession("https://accounts.google.com", "sub-"+pamUser, pamUser+"@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetLink(sess.Iss, sess.Sub, pamUser); err != nil {
		t.Fatal(err)
	}
	sess.PAMUser = pamUser
	if err := st.SaveSession(sess); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: s.cookieName(), Value: sess.ID}
}

func do(s *Server, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func cookieNamed(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestJailDotDotAndEncoded(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "ok.txt"), []byte("ok"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("root:x"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/home/ok.txt",
		"/home/./ok.txt",
		"/home/foo/../ok.txt",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(c)
		rr := do(s, req)
		if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
			t.Fatalf("allow %s: %d %q", path, rr.Code, rr.Body.String())
		}
	}
	for _, path := range []string{
		"/home/../alice/ok.txt",
		"/home/../secret",
		"/home/%2e%2e/ok.txt",
		"/home/%2e%2e/secret",
		"/home/foo/%2e%2e/%2e%2e/etc/passwd",
		"/home/foo/../../secret",
		"/home/ok.txt/../../../secret",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(c)
		rr := do(s, req)
		if rr.Code == http.StatusOK && rr.Body.String() == "ok" && path == "/home/../alice/ok.txt" {
			t.Fatalf("%s served by leaving /home", path)
		}
		if strings.Contains(rr.Body.String(), "root:") {
			t.Fatalf("%s leaked: %s", path, rr.Body.String())
		}
		if rr.Code == http.StatusOK && rr.Body.String() == "root:x" {
			t.Fatalf("%s read outside cubby", path)
		}
	}
}

func TestAliceCannotReadBob(t *testing.T) {
	s, st, dir := testServer(t)
	alice := linkedSession(t, s, st, "alice")
	_ = linkedSession(t, s, st, "bob")
	if err := os.WriteFile(filepath.Join(dir, "users", "bob", "secret.txt"), []byte("bobsecret"), 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/secret.txt", nil)
	req.AddCookie(alice)
	rr := do(s, req)
	if rr.Code == http.StatusOK {
		t.Fatal("alice should not see bob's filename in her jail")
	}
	req = httptest.NewRequest(http.MethodPut, "/home/../bob/hack.txt", strings.NewReader("x"))
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(alice)
	rr = do(s, req)
	if rr.Code == http.StatusCreated {
		t.Fatal("alice wrote into bob")
	}
	if _, err := os.Stat(filepath.Join(dir, "users", "bob", "hack.txt")); err == nil {
		t.Fatal("bob tree mutated")
	}
}

func TestHomeLoginRedirect(t *testing.T) {
	s, st, _ := testServer(t)
	rr := do(s, httptest.NewRequest(http.MethodGet, "/home/", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("GET no cookie: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	rr = do(s, httptest.NewRequest(http.MethodPut, "/home/x", strings.NewReader("x")))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("PUT no cookie: %d", rr.Code)
	}

	sess, err := st.CreateSession("https://accounts.google.com", "sub-x", "x@y.z", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: s.cookieName(), Value: sess.ID}
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/link" {
		t.Fatalf("GET unlinked: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodPut, "/home/x", strings.NewReader("x"))
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("PUT unlinked: %d", rr.Code)
	}
}

func TestUnlinkHTTPGone(t *testing.T) {
	s, _, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/unlink", nil)
	rr := do(s, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("POST /unlink => %d", rr.Code)
	}
}

func TestLogoutDropsSessionKeepsLink(t *testing.T) {
	s, st, _ := testServer(t)
	c := linkedSession(t, s, st, "alice")
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `action="/logout"`) {
		t.Fatalf("listing: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Sign out") || !strings.Contains(rr.Body.String(), "alice@example.com") || !strings.Contains(rr.Body.String(), " · alice") {
		t.Fatalf("chrome: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "/unlink") {
		t.Fatal("unlink in HTML")
	}

	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("csrf: %d", rr.Code)
	}
	if _, err := st.GetSession(c.Value); err != nil {
		t.Fatal("csrf must not delete session")
	}

	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("logout: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := st.GetSession(c.Value); !os.IsNotExist(err) {
		t.Fatalf("session remains: %v", err)
	}
	if pam, ok, err := st.LookupLink("https://accounts.google.com", "sub-alice"); err != nil || !ok || pam != "alice" {
		t.Fatalf("link pam=%s ok=%v err=%v", pam, ok, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("after logout GET /home/ => %d %s", rr.Code, rr.Header().Get("Location"))
	}
}

func TestLogoutCSRF(t *testing.T) {
	s, st, _ := testServer(t)
	c := linkedSession(t, s, st, "alice")
	tests := []struct {
		name, origin, site, referer string
		want                        int
	}{
		{"origin", "https://stash.test", "", "", http.StatusFound},
		{"bad origin", "https://evil.test", "same-origin", "", http.StatusForbidden},
		{"null origin same-fetch", "null", "same-origin", "", http.StatusFound},
		{"null origin none with referer", "null", "none", "https://stash.test/home/", http.StatusFound},
		{"null origin none no referer", "null", "none", "", http.StatusForbidden},
		{"fetch same-origin", "", "same-origin", "", http.StatusFound},
		{"fetch none with referer", "", "none", "https://stash.test/home/", http.StatusFound},
		{"fetch none no referer", "", "none", "", http.StatusForbidden},
		{"no headers", "", "", "", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/logout", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.site != "" {
				req.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			req.AddCookie(c)
			rr := do(s, req)
			if rr.Code != tc.want {
				t.Fatalf("%d want %d %s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestRange(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	body := []byte("abcdefghij")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "x.bin"), body, 0660); err != nil {
		t.Fatal(err)
	}
	full := string(body)
	tests := []struct {
		hdr      string
		wantCode int
		wantBody string
		allow200 bool
	}{
		{"bytes=0-2", http.StatusPartialContent, "abc", false},
		{"bytes=-3", http.StatusPartialContent, "hij", false},
		{"bytes=99-100", http.StatusRequestedRangeNotSatisfiable, "", false},
		{"bytes=0-0", http.StatusPartialContent, "a", false},
		{"bytes=0-", http.StatusPartialContent, full, true},
		{"bytes=-1", http.StatusPartialContent, "j", false},
		{"bytes=0-999999999999999999", http.StatusPartialContent, full, true},
		{"bytes=5-4", http.StatusRequestedRangeNotSatisfiable, "", false},
		{"bytes=0-1,3-4", http.StatusPartialContent, "", true},
		{"bytes=nonesuch", http.StatusRequestedRangeNotSatisfiable, "", true},
		{"", http.StatusOK, full, false},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "/home/x.bin", nil)
		if tc.hdr != "" {
			req.Header.Set("Range", tc.hdr)
		}
		req.AddCookie(c)
		rr := do(s, req)
		code := rr.Code
		if code == http.StatusInternalServerError {
			t.Fatalf("%q: 500 %s", tc.hdr, rr.Body.String())
		}
		ok := code == tc.wantCode || (tc.allow200 && code == http.StatusOK)
		if !ok {
			t.Fatalf("%q: %d want %d", tc.hdr, code, tc.wantCode)
		}
		got := rr.Body.String()
		if code == http.StatusOK {
			if got != full {
				t.Fatalf("%q 200 body %q", tc.hdr, got)
			}
			continue
		}
		if tc.wantBody != "" && got != tc.wantBody {
			t.Fatalf("%q body %q want %q", tc.hdr, got, tc.wantBody)
		}
		if strings.Contains(got, "root:") {
			t.Fatalf("%q leaked %q", tc.hdr, got)
		}
	}
}

func TestUploadCSRFAndOversize(t *testing.T) {
	s, st, _ := testServer(t)
	c := linkedSession(t, s, st, "alice")
	req := httptest.NewRequest(http.MethodPut, "/home/a.txt", strings.NewReader("hello"))
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("csrf: %d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/home/a.txt", strings.NewReader("hello"))
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}
	big := bytes.Repeat([]byte("x"), 200)
	req = httptest.NewRequest(http.MethodPut, "/home/big.txt", bytes.NewReader(big))
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusRequestEntityTooLarge && rr.Code != http.StatusInternalServerError {
		// MaxBytesReader may surface as 500 on some Go versions if WriteHeader already sent
		if rr.Code == http.StatusCreated {
			t.Fatal("oversize accepted")
		}
	}
}

func TestAdminSeamHasNoExtraHTTP(t *testing.T) {
	s, st, _ := testServer(t)
	cfg := *s.config()
	cfg.AdminUsers = []string{"alice"}
	s.SetConfig(&cfg)
	c := linkedSession(t, s, st, "alice")
	sess, err := st.GetSession(c.Value)
	if err != nil || !s.isAdmin(sess) {
		t.Fatalf("admin seam: err=%v sess=%v", err, sess)
	}
	bob := linkedSession(t, s, st, "bob")
	bsess, err := st.GetSession(bob.Value)
	if err != nil || s.isAdmin(bsess) {
		t.Fatalf("bob admin=%v err=%v", s.isAdmin(bsess), err)
	}
}

func TestUploadFilenameJail(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	req := httptest.NewRequest(http.MethodPut, "/home/../escape.txt", strings.NewReader("x"))
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code == http.StatusCreated {
		t.Fatal("escaped put")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.txt")); err == nil {
		t.Fatal("wrote outside user dir")
	}
}

func TestBadPAMDoesNotLink(t *testing.T) {
	s, st, _ := testServer(t)
	sess, err := st.CreateSession("https://accounts.google.com", "sub-z", "z@z.z", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/link", strings.NewReader("username=alice&password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(&http.Cookie{Name: s.cookieName(), Value: sess.ID})
	rr := do(s, req)
	if rr.Code == http.StatusFound {
		t.Fatal("linked with bad password")
	}
	_, ok, err := st.LookupLink(sess.Iss, sess.Sub)
	if err != nil || ok {
		t.Fatalf("link written ok=%v err=%v", ok, err)
	}
}

func TestGoodPAMLinksCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		t.Skip("uid 0 cannot link")
	}
	s, st, _ := testServer(t)
	s.pam = mapPAM{u.Username: "pw"}
	sess, err := st.CreateSession("https://accounts.google.com", "sub-me", u.Username+"@x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := "username=" + u.Username + "&password=pw"
	req := httptest.NewRequest(http.MethodPost, "/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(&http.Cookie{Name: s.cookieName(), Value: sess.ID})
	rr := do(s, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("link: %d %s", rr.Code, rr.Body.String())
	}
	pam, ok, err := st.LookupLink(sess.Iss, sess.Sub)
	if err != nil || !ok || pam != u.Username {
		t.Fatalf("pam=%s ok=%v err=%v", pam, ok, err)
	}
	stt, err := os.Stat(filepath.Join(s.config().Data, "users", u.Username))
	if err != nil {
		t.Fatal(err)
	}
	if stt.Mode()&os.ModeSetgid == 0 || stt.Mode().Perm() != 0770 {
		t.Fatalf("cubby mode %s", stt.Mode())
	}
}

func TestUID0DoesNotLink(t *testing.T) {
	root, err := user.LookupId("0")
	if err != nil {
		t.Skip(err)
	}
	if !pamauth.ValidUsername(root.Username) {
		t.Skip("root name")
	}
	s, st, dir := testServer(t)
	s.pam = mapPAM{root.Username: "pw"}
	sess, err := st.CreateSession("https://accounts.google.com", "sub-root", "root@x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := "username=" + root.Username + "&password=pw"
	req := httptest.NewRequest(http.MethodPost, "/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(&http.Cookie{Name: s.cookieName(), Value: sess.ID})
	rr := do(s, req)
	if rr.Code == http.StatusFound {
		t.Fatal("linked uid 0")
	}
	_, ok, err := st.LookupLink(sess.Iss, sess.Sub)
	if err != nil || ok {
		t.Fatalf("link written ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "users", root.Username)); err == nil {
		t.Fatal("created root cubby")
	}
}

func googleLogin(t *testing.T, s *Server) (state string, tx *http.Cookie) {
	t.Helper()
	rr := do(s, httptest.NewRequest(http.MethodGet, "/login?provider=google", nil))
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "accounts.google.com") {
		t.Fatalf("login: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state = loc.Query().Get("state")
	if state == "" {
		t.Fatal("missing state")
	}
	tx = cookieNamed(rr, s.oauthCookieName())
	if tx == nil || tx.Value == "" {
		t.Fatal("missing oauth cookie")
	}
	return state, tx
}

func oauthCallback(state string, tx *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?state="+state+"&code=zz", nil)
	if tx != nil {
		req.AddCookie(tx)
	}
	return req
}

func TestCallbackSetsCookie(t *testing.T) {
	s, _, _ := testServer(t)
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/link" {
		t.Fatalf("location %s", loc)
	}
	if cookieNamed(rr, s.cookieName()) == nil {
		t.Fatal("missing session cookie")
	}
}

func TestCallbackRejects(t *testing.T) {
	tests := []struct {
		name string
		prep func(*testing.T, *Server) *http.Request
	}{
		{"without cookie", func(t *testing.T, s *Server) *http.Request {
			state, _ := googleLogin(t, s)
			return oauthCallback(state, nil)
		}},
		{"wrong cookie", func(t *testing.T, s *Server) *http.Request {
			state, _ := googleLogin(t, s)
			_, tx2 := googleLogin(t, s)
			return oauthCallback(state, tx2)
		}},
		{"expired", func(t *testing.T, s *Server) *http.Request {
			state, tx := googleLogin(t, s)
			nonce, err := s.verifyState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.putOauthTx(tx.Value, nonce, "", time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			return oauthCallback(state, tx)
		}},
		{"attacker state", func(t *testing.T, s *Server) *http.Request {
			state, _ := googleLogin(t, s)
			_, victim := googleLogin(t, s)
			return oauthCallback(state, victim)
		}},
		{"no login", func(t *testing.T, s *Server) *http.Request {
			state, err := s.signState("n")
			if err != nil {
				t.Fatal(err)
			}
			return oauthCallback(state, nil)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := testServer(t)
			rr := do(s, tc.prep(t, s))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%d %s", rr.Code, rr.Body.String())
			}
			if cookieNamed(rr, s.cookieName()) != nil {
				t.Fatal("session cookie")
			}
		})
	}
}

func TestCallbackRejectsReplay(t *testing.T) {
	s, _, _ := testServer(t)
	state, tx := googleLogin(t, s)
	rr := do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound {
		t.Fatalf("first: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOauthTxCap(t *testing.T) {
	s, _, _ := testServer(t)
	for i := 0; i < oauthMaxTx; i++ {
		googleLogin(t, s)
	}
	rr := do(s, httptest.NewRequest(http.MethodGet, "/login?provider=google", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("over cap: %d %s", rr.Code, rr.Body.String())
	}
	if cookieNamed(rr, s.oauthCookieName()) != nil {
		t.Fatal("oauth cookie over cap")
	}
}

func TestOauthTxPurgeExpired(t *testing.T) {
	s, _, _ := testServer(t)
	for i := 0; i < oauthMaxTx; i++ {
		if err := s.putOauthTx(fmt.Sprintf("%064x", i), "n", "v", time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	rr := do(s, httptest.NewRequest(http.MethodGet, "/login?provider=google", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("expired full: %d %s", rr.Code, rr.Body.String())
	}
	if cookieNamed(rr, s.oauthCookieName()) == nil {
		t.Fatal("missing oauth cookie")
	}
}

func TestStaticCSSTheming(t *testing.T) {
	s, _, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	rr := do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("css: %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"color-scheme: light dark",
		"--bg:",
		"--panel:",
		"prefers-color-scheme: dark",
		"min-height: 44px",
		"flex-wrap: nowrap",
		"text-overflow: ellipsis",
		"kind name name name del",
		"justify-self: end",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("css missing %q", want)
		}
	}
}

func TestHTMLPages(t *testing.T) {
	s, st, dir := testServer(t)

	rr := do(s, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d", rr.Code)
	}
	login := rr.Body.String()
	for _, want := range []string{
		`class="door"`,
		`class="brand"`,
		`href="/login?provider=google"`,
		"Sign in with Google",
		`class="btn"`,
	} {
		if !strings.Contains(login, want) {
			t.Fatalf("login missing %q: %s", want, login)
		}
	}
	if strings.Contains(login, `class="top"`) || strings.Contains(login, "Sign out") || strings.Contains(login, "/unlink") {
		t.Fatalf("login chrome: %s", login)
	}
	if strings.Contains(login, "<h1>") || strings.Contains(login, "Pick up bootstrap") {
		t.Fatalf("login extra copy: %s", login)
	}

	sess, err := st.CreateSession("https://accounts.google.com", "sub-x", "x@y.z", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: s.cookieName(), Value: sess.ID}
	req := httptest.NewRequest(http.MethodGet, "/link", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("link: %d", rr.Code)
	}
	link := rr.Body.String()
	for _, want := range []string{
		`action="/logout"`,
		"Sign out",
		`action="/link"`,
		`name="username"`,
		`name="password"`,
		`class="reveal"`,
		`aria-label="Show password"`,
		`class="eye"`,
		`class="brand"`,
		"Not linked yet",
	} {
		if !strings.Contains(link, want) {
			t.Fatalf("link missing %q: %s", want, link)
		}
	}

	cookie := linkedSession(t, s, st, "alice")
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(cookie)
	rr = do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("empty listing: %d %s", rr.Code, rr.Body.String())
	}
	empty := rr.Body.String()
	for _, want := range []string{"Files", `class="add dir"`, `class="add file"`, `name="file"`, `name="mkdir"`, "browse", "➕", "📁", "📄", `class="plus"`, `class="kind"`, `id="upload-label"`} {
		if !strings.Contains(empty, want) {
			t.Fatalf("empty listing missing %q: %s", want, empty)
		}
	}
	if strings.Contains(empty, "Nothing here yet.") || strings.Contains(empty, ">Upload<") {
		t.Fatalf("empty listing chrome: %s", empty)
	}
	if strings.Contains(empty, "⬇️") {
		t.Fatalf("empty listing download mark: %s", empty)
	}
	if strings.Contains(empty, `class="copy"`) {
		t.Fatalf("empty listing copy: %s", empty)
	}

	sub := filepath.Join(dir, "users", "alice", "kit")
	if err := os.Mkdir(sub, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.txt"), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/home/kit/", nil)
	req.AddCookie(cookie)
	rr = do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("nested listing: %d %s", rr.Code, rr.Body.String())
	}
	nested := rr.Body.String()
	for _, want := range []string{
		`href="/home/"`,
		">Files<",
		">kit<",
		"a.txt",
		"1 B",
		`name="delete"`,
		"🗑️",
		`class="copy"`,
		`aria-label="Copy link"`,
		`class="mark"`,
		"⬇️",
	} {
		if !strings.Contains(nested, want) {
			t.Fatalf("nested listing missing %q: %s", want, nested)
		}
	}
}

func TestHTMLErrorPages(t *testing.T) {
	s, st, _ := testServer(t)
	rr := do(s, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("404: %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content-type %s", rr.Header().Get("Content-Type"))
	}
	body := rr.Body.String()
	for _, want := range []string{
		`class="door"`,
		`class="brand"`,
		"That page is not here.",
		`href="/"`,
		`class="btn"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("404 missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "404 page not found") {
		t.Fatal("stdlib 404")
	}

	rr = do(s, httptest.NewRequest(http.MethodGet, "/login?provider=nope", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("unknown provider: %d %s", rr.Code, rr.Header().Get("Location"))
	}

	rr = do(s, httptest.NewRequest(http.MethodGet, "/logout", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/" {
		t.Fatalf("GET logout: %d %s", rr.Code, rr.Header().Get("Location"))
	}

	c := linkedSession(t, s, st, "alice")
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "Sign out") {
		t.Fatalf("signed 404: %d %s", rr.Code, rr.Body.String())
	}

	state, _ := googleLogin(t, s)
	req = oauthCallback(state, nil)
	rr = do(s, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "Sign in with Google") {
		t.Fatalf("callback html: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Sign-in expired") {
		t.Fatalf("callback msg: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "This request was rejected.") {
		t.Fatalf("csrf html: %d %s", rr.Code, rr.Body.String())
	}
}

func TestHTMLCubbyErrors(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "users", "alice", "out")); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "🔗") {
		t.Fatalf("symlink listing: %d %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/home/out", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid path") {
		t.Fatalf("api symlink: %d %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/home/out", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("html symlink: %d %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/home/" {
		t.Fatalf("html symlink location %s", loc)
	}
	notice := cookieNamed(rr, s.noticeCookieName())
	if notice == nil || notice.Value != "not-allowed" {
		t.Fatalf("html symlink notice cookie %+v", notice)
	}
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	req.AddCookie(notice)
	rr = do(s, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, "That path is not allowed.") {
		t.Fatalf("html symlink notice: %d %s", rr.Code, body)
	}
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if strings.Contains(rr.Body.String(), "That path is not allowed.") {
		t.Fatalf("notice should not survive refresh: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/home/missing.txt", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("html missing: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	notice = cookieNamed(rr, s.noticeCookieName())
	if notice == nil || notice.Value != "missing" {
		t.Fatalf("html missing notice cookie %+v", notice)
	}
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	req.AddCookie(notice)
	rr = do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "That file is gone.") {
		t.Fatalf("html missing notice: %d %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/home/?err=denied", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if strings.Contains(rr.Body.String(), "Not authorized to open that.") {
		t.Fatalf("query err should be ignored: %s", rr.Body.String())
	}
}

func TestHTMLDownloadMark(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "a.txt"), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/a.txt", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("download: %d %s", rr.Code, rr.Body.String())
	}
	dl := cookieNamed(rr, s.downloadCookieName())
	if dl == nil || dl.Value != "a.txt" {
		t.Fatalf("download cookie %+v", dl)
	}
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	req.AddCookie(dl)
	rr = do(s, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, `class="mark">⬇️`) {
		t.Fatalf("download mark: %d %s", rr.Code, body)
	}
	req = httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if strings.Contains(rr.Body.String(), `class="mark">⬇️`) {
		t.Fatalf("mark should not survive refresh: %s", rr.Body.String())
	}
}

func TestPutOverwrite(t *testing.T) {
	s, st, _ := testServer(t)
	c := linkedSession(t, s, st, "alice")
	for _, body := range []string{"one", "two"} {
		req := httptest.NewRequest(http.MethodPut, "/home/f.txt", strings.NewReader(body))
		req.Header.Set("Origin", "https://stash.test")
		req.AddCookie(c)
		rr := do(s, req)
		if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
			t.Fatalf("put %s: %d", body, rr.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/home/f.txt", nil)
	req.AddCookie(c)
	rr := do(s, req)
	got, _ := io.ReadAll(rr.Result().Body)
	if string(got) != "two" {
		t.Fatalf("got %q", got)
	}
}

func TestPutFailurePreservesExisting(t *testing.T) {
	s, st, _ := testServer(t)
	c := linkedSession(t, s, st, "alice")
	req := httptest.NewRequest(http.MethodPut, "/home/keep.txt", strings.NewReader("keep-me"))
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed: %d %s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodPut, "/home/keep.txt", &failAfter{rest: []byte("xxxx"), err: io.ErrUnexpectedEOF})
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	_ = do(s, req)
	req = httptest.NewRequest(http.MethodGet, "/home/keep.txt", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "keep-me" {
		t.Fatalf("preserved: %d %q", rr.Code, rr.Body.String())
	}
}

type failAfter struct {
	rest []byte
	err  error
}

func (f *failAfter) Read(p []byte) (int, error) {
	if len(f.rest) == 0 {
		return 0, f.err
	}
	n := copy(p, f.rest)
	f.rest = f.rest[n:]
	return n, nil
}

func TestDeleteOwnFile(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	path := filepath.Join(dir, "users", "alice", "gone.txt")
	if err := os.WriteFile(path, []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/home/gone.txt", nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("csrf: %d", rr.Code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("csrf delete removed file")
	}
	req = httptest.NewRequest(http.MethodDelete, "/home/gone.txt", nil)
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file still present")
	}
}

func TestDeleteFormAndNonEmptyDir(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	sub := filepath.Join(dir, "users", "alice", "d")
	if err := os.Mkdir(sub, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f.txt"), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/home/", strings.NewReader("delete=1&name=d"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("non-empty: %d %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if loc != "/home/" {
		t.Fatalf("non-empty location %s", loc)
	}
	noticeCookie := cookieNamed(rr, s.noticeCookieName())
	if noticeCookie == nil || noticeCookie.Value != "not-empty" {
		t.Fatalf("non-empty notice cookie %+v", noticeCookie)
	}
	if _, err := os.Stat(sub); err != nil {
		t.Fatal("non-empty delete removed dir")
	}
	req = httptest.NewRequest(http.MethodGet, loc, nil)
	req.AddCookie(c)
	req.AddCookie(noticeCookie)
	rr = do(s, req)
	notice := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(notice, "still has files") {
		t.Fatalf("non-empty notice: %d %s", rr.Code, notice)
	}
	req = httptest.NewRequest(http.MethodGet, loc, nil)
	req.AddCookie(c)
	rr = do(s, req)
	if strings.Contains(rr.Body.String(), "still has files") {
		t.Fatalf("notice should not survive refresh: %s", rr.Body.String())
	}
	if err := os.Remove(filepath.Join(sub, "f.txt")); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/home/", strings.NewReader("delete=1&name=d"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("form delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatal("dir still present")
	}
}

func TestDeleteDoesNotEscape(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	outside := filepath.Join(dir, "secret")
	if err := os.WriteFile(outside, []byte("no"), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/home/../secret", nil)
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code == http.StatusNoContent {
		t.Fatal("escaped delete")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("deleted outside jail")
	}
}

func checkCookieFlags(t *testing.T, c *http.Cookie, name string, secure bool) {
	t.Helper()
	if c == nil {
		t.Fatalf("missing %s", name)
	}
	if c.Name != name {
		t.Fatalf("name %s want %s", c.Name, name)
	}
	if c.Path != "/" {
		t.Fatalf("path %s", c.Path)
	}
	if !c.HttpOnly {
		t.Fatal("httponly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("samesite %v", c.SameSite)
	}
	if c.Secure != secure {
		t.Fatalf("secure %v want %v", c.Secure, secure)
	}
}

func TestHTTPSCookieFlags(t *testing.T) {
	s, _, _ := testServer(t)
	state, tx := googleLogin(t, s)
	checkCookieFlags(t, tx, "__Host-bootstash-oauth", true)
	rr := do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	checkCookieFlags(t, cookieNamed(rr, s.cookieName()), "__Host-bootstash", true)
}

func TestHTTPCookieFlags(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.PublicURL = "http://stash.test"
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, st, fakeIDP{}, mapPAM{"alice": "secret"}, bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	state, tx := googleLogin(t, s)
	checkCookieFlags(t, tx, "bootstash_oauth", false)
	rr := do(s, oauthCallback(state, tx))
	if rr.Code != http.StatusFound {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	checkCookieFlags(t, cookieNamed(rr, s.cookieName()), "bootstash", false)
}

func TestContentDisposition(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	tests := []struct {
		name string
		disp string
	}{
		{"note.txt", "attachment"},
		{"x.bin", "attachment"},
		{"pic.jpg", "inline"},
		{"pic.png", "inline"},
		{"doc.pdf", "inline"},
		{"song.mp3", "inline"},
		{"clip.mp4", "inline"},
		{"my file.txt", "attachment"},
		{"client.ovpn", "inline"},
	}
	for _, tc := range tests {
		p := filepath.Join(dir, "users", "alice", tc.name)
		if err := os.WriteFile(p, []byte("x"), 0660); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/home/"+url.PathEscape(tc.name), nil)
		req.AddCookie(c)
		rr := do(s, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
		}
		mediatype, params, err := mime.ParseMediaType(rr.Header().Get("Content-Disposition"))
		if err != nil {
			t.Fatalf("%s: %v %q", tc.name, err, rr.Header().Get("Content-Disposition"))
		}
		if mediatype != tc.disp {
			t.Fatalf("%s disp %q want %q", tc.name, mediatype, tc.disp)
		}
		if params["filename"] != tc.name {
			t.Fatalf("%s filename %q", tc.name, params["filename"])
		}
		if tc.name == "client.ovpn" && rr.Header().Get("Content-Type") != ovpnProfileType {
			t.Fatalf("ovpn type %q", rr.Header().Get("Content-Type"))
		}
	}
}

func TestContentDispositionFilenameEncoding(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	name := `say "hi".txt`
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", name), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/"+url.PathEscape(name), nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	_, params, err := mime.ParseMediaType(rr.Header().Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("%v %q", err, rr.Header().Get("Content-Disposition"))
	}
	if params["filename"] != name {
		t.Fatalf("filename %q want %q (%q)", params["filename"], name, rr.Header().Get("Content-Disposition"))
	}
}

func TestResponseSecurityHeaders(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "a.txt"), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	reqs := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/login", nil),
		httptest.NewRequest(http.MethodGet, "/home/", nil),
		httptest.NewRequest(http.MethodGet, "/home/a.txt", nil),
		httptest.NewRequest(http.MethodGet, "/static/style.css", nil),
		httptest.NewRequest(http.MethodHead, "/openvpn-api/profile", nil),
	}
	var missing []string
	for _, req := range reqs {
		if strings.HasPrefix(req.URL.Path, "/home") {
			req.AddCookie(c)
		}
		rr := do(s, req)
		if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			missing = append(missing, req.URL.Path+" nosniff")
		}
		if rr.Header().Get("Referrer-Policy") != "same-origin" {
			missing = append(missing, req.URL.Path+" referrer")
		}
		if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			missing = append(missing, req.URL.Path+" csp")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%s", strings.Join(missing, ", "))
	}
}

func TestLinkRotatesSessionCookie(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if u.Uid == "0" {
		t.Skip("uid 0 cannot link")
	}
	if !pamauth.ValidUsername(u.Username) {
		t.Skip("name")
	}
	s, st, _ := testServer(t)
	s.pam = mapPAM{u.Username: "pw"}
	sess, err := st.CreateSession("https://accounts.google.com", "sub-rot", u.Username+"@x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := "username=" + u.Username + "&password=pw"
	req := httptest.NewRequest(http.MethodPost, "/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://stash.test")
	req.AddCookie(&http.Cookie{Name: s.cookieName(), Value: sess.ID})
	rr := do(s, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("link: %d %s", rr.Code, rr.Body.String())
	}
	got := cookieNamed(rr, s.cookieName())
	if got == nil || got.Value == sess.ID {
		t.Fatalf("cookie %+v old %s", got, sess.ID)
	}
	if _, err := st.GetSession(sess.ID); !os.IsNotExist(err) {
		t.Fatalf("old session: %v", err)
	}
	linked, err := st.GetSession(got.Value)
	if err != nil || linked.PAMUser != u.Username {
		t.Fatalf("%+v %v", linked, err)
	}
}

func TestOpenVPNProfileImport(t *testing.T) {
	s, st, dir := testServer(t)
	head := do(s, httptest.NewRequest(http.MethodHead, "/openvpn-api/profile?embedded=true", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD: %d %s", head.Code, head.Body.String())
	}
	if head.Header().Get("Ovpn-WebAuth") != ovpnWebAuth {
		t.Fatalf("HEAD Ovpn-WebAuth %q", head.Header().Get("Ovpn-WebAuth"))
	}

	rr := do(s, httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET anon: %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Ovpn-WebAuth") != ovpnWebAuth {
		t.Fatalf("GET anon Ovpn-WebAuth %q", rr.Header().Get("Ovpn-WebAuth"))
	}
	if !strings.Contains(rr.Body.String(), "Sign in with Google") {
		t.Fatalf("GET anon login: %s", rr.Body.String())
	}
	if cookieNamed(rr, s.ovpnImportCookieName()) == nil {
		t.Fatal("GET anon missing ovpn cookie")
	}

	rest := do(s, httptest.NewRequest(http.MethodGet, "/rest/GetUserlogin", nil))
	if rest.Code != http.StatusUnauthorized {
		t.Fatalf("REST: %d %s", rest.Code, rest.Body.String())
	}
	if rest.Header().Get("Ovpn-WebAuth") != ovpnWebAuth {
		t.Fatalf("REST Ovpn-WebAuth %q", rest.Header().Get("Ovpn-WebAuth"))
	}
	if rest.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("REST must not challenge Basic")
	}
	body := rest.Body.String()
	if !strings.Contains(body, "<Error>") || !strings.Contains(body, "Ovpn-WebAuth: "+ovpnWebAuth) {
		t.Fatalf("REST xml: %s", body)
	}
	auto := do(s, httptest.NewRequest(http.MethodGet, "/rest/GetAutologin", nil))
	if auto.Code != http.StatusUnauthorized || auto.Header().Get("Ovpn-WebAuth") != ovpnWebAuth {
		t.Fatalf("GetAutologin: %d %s", auto.Code, auto.Header().Get("Ovpn-WebAuth"))
	}

	sess, err := st.CreateSession("https://accounts.google.com", "sub-ovpn", "x@y.z", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	unlinked := &http.Cookie{Name: s.cookieName(), Value: sess.ID}
	req := httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.AddCookie(unlinked)
	rr = do(s, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/link" {
		t.Fatalf("GET unlinked: %d %s", rr.Code, rr.Header().Get("Location"))
	}

	c := linkedSession(t, s, st, "alice")
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("GET linked empty: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), ".ovpn") {
		t.Fatalf("html empty: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "openvpn://import-profile/") {
		t.Fatal("html empty minted a token")
	}

	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "client.ovpn"), []byte("client"), 0660); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("auto ovpn: %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != ovpnProfileType {
		t.Fatalf("auto ovpn type %q", rr.Header().Get("Content-Type"))
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("auto ovpn disposition %q", rr.Header().Get("Content-Disposition"))
	}
	if !hasOvpnTitle(rr.Body.String(), "client", "client") {
		t.Fatalf("auto ovpn body %q", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?deviceID=abc&auth=webauth", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("html handoff: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	page := rr.Body.String()
	if !strings.Contains(page, "client.ovpn") || !strings.Contains(page, "download=1") {
		t.Fatalf("html handoff body: %s", page)
	}
	if strings.Contains(page, `download="`) {
		t.Fatal("html handoff must not force a save-only download attribute")
	}
	urls := ovpnImportHTTPS(page)
	if len(urls) != 1 {
		t.Fatalf("html handoff tokens %d: %s", len(urls), page)
	}
	u, err := url.Parse(urls[0])
	if err != nil || u.Path != "/openvpn-api/profile" || u.Query().Get("token") == "" {
		t.Fatalf("import url %q: %v", urls[0], err)
	}

	headTok := do(s, httptest.NewRequest(http.MethodHead, u.RequestURI(), nil))
	if headTok.Code != http.StatusOK || headTok.Header().Get("Ovpn-WebAuth") != "" {
		t.Fatalf("token HEAD: %d webauth=%q", headTok.Code, headTok.Header().Get("Ovpn-WebAuth"))
	}
	if headTok.Header().Get("Content-Type") != ovpnProfileType {
		t.Fatalf("token HEAD type %q", headTok.Header().Get("Content-Type"))
	}

	got := do(s, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
	if got.Code != http.StatusOK || got.Header().Get("Ovpn-WebAuth") != "" {
		t.Fatalf("token GET: %d webauth=%q %s", got.Code, got.Header().Get("Ovpn-WebAuth"), got.Body.String())
	}
	if got.Header().Get("Content-Type") != ovpnProfileType || !hasOvpnTitle(got.Body.String(), "client", "client") {
		t.Fatalf("token GET %q %q", got.Header().Get("Content-Type"), got.Body.String())
	}
	got2 := do(s, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
	if got2.Code != http.StatusOK || !hasOvpnTitle(got2.Body.String(), "client", "client") {
		t.Fatalf("token GET2: %d %s", got2.Code, got2.Body.String())
	}
	got3 := do(s, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
	if got3.Code != http.StatusNotFound {
		t.Fatalf("token GET3: %d", got3.Code)
	}
	miss := do(s, httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?token=deadbeefdeadbeefdeadbeefdeadbeef", nil))
	if miss.Code != http.StatusNotFound || miss.Header().Get("Ovpn-WebAuth") != "" {
		t.Fatalf("bad token: %d webauth=%q", miss.Code, miss.Header().Get("Ovpn-WebAuth"))
	}

	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?download=1", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != ovpnProfileType {
		t.Fatalf("download=1: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download=1 disposition %q", rr.Header().Get("Content-Disposition"))
	}
	if !hasOvpnTitle(rr.Body.String(), "client", "client") {
		t.Fatalf("download=1 body %q", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?embedded=true", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "PROFILE_DOWNLOAD_SUCCESS") {
		t.Fatalf("embedded: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "client") {
		t.Fatalf("embedded profile: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "FRIENDLY_NAME") {
		t.Fatalf("embedded title: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/home/client.ovpn", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ovpn: %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != ovpnProfileType {
		t.Fatalf("ovpn type %q", rr.Header().Get("Content-Type"))
	}
	if rr.Body.String() != "client" {
		t.Fatalf("ovpn body %q", rr.Body.String())
	}
	if cookieNamed(rr, s.downloadCookieName()) != nil {
		t.Fatal("inline ovpn should not mark download")
	}

	if err := os.Remove(filepath.Join(dir, "users", "alice", "client.ovpn")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "work.ovpn"), []byte("work"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "home.ovpn"), []byte("home"), 0660); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/home/" {
		t.Fatalf("several non-html: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	page = rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(page, "work.ovpn") || !strings.Contains(page, "home.ovpn") {
		t.Fatalf("picker: %d %s", rr.Code, page)
	}
	if strings.Contains(page, "location.replace") || strings.Contains(page, `id="ovpn-open"`) {
		t.Fatal("picker must not auto-open")
	}
	urls = ovpnImportHTTPS(page)
	if len(urls) != 2 {
		t.Fatalf("picker tokens %d: %s", len(urls), page)
	}
	bodies := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		got := do(s, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
		if got.Code != http.StatusOK || got.Header().Get("Ovpn-WebAuth") != "" {
			t.Fatalf("picker token: %d webauth=%q %s", got.Code, got.Header().Get("Ovpn-WebAuth"), got.Body.String())
		}
		bodies[got.Body.String()] = true
	}
	var sawWork, sawHome bool
	for b := range bodies {
		if hasOvpnTitle(b, "work", "work") {
			sawWork = true
		}
		if hasOvpnTitle(b, "home", "home") {
			sawHome = true
		}
	}
	if !sawWork || !sawHome {
		t.Fatalf("picker bodies %v", bodies)
	}

	rr = do(s, httptest.NewRequest(http.MethodPost, "/openvpn-api/profile", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rr.Code)
	}
}

func TestOpenVPNTokenDisable(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "client.ovpn"), []byte("client"), 0660); err != nil {
		t.Fatal(err)
	}

	cfg := *s.config()
	cfg.DisableOvpnToken = true
	s.SetConfig(&cfg)

	head := do(s, httptest.NewRequest(http.MethodHead, "/openvpn-api/profile", nil))
	if head.Code != http.StatusOK || head.Header().Get("Ovpn-WebAuth") != "" {
		t.Fatalf("HEAD operator off: %d webauth=%q", head.Code, head.Header().Get("Ovpn-WebAuth"))
	}
	rest := do(s, httptest.NewRequest(http.MethodGet, "/rest/GetUserlogin", nil))
	if rest.Code != http.StatusUnauthorized || rest.Header().Get("Ovpn-WebAuth") != "" {
		t.Fatalf("REST operator off: %d webauth=%q", rest.Code, rest.Header().Get("Ovpn-WebAuth"))
	}
	if strings.Contains(rest.Body.String(), "Ovpn-WebAuth") {
		t.Fatalf("REST operator off body: %s", rest.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr := do(s, req)
	page := rr.Body.String()
	if rr.Code != http.StatusOK || strings.Contains(page, "openvpn://import-profile/") {
		t.Fatalf("html operator off: %d %s", rr.Code, page)
	}
	if !strings.Contains(page, "download=1") || !strings.Contains(page, "Save") {
		t.Fatalf("html operator off save: %s", page)
	}

	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?download=1", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != ovpnProfileType {
		t.Fatalf("download operator off: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}

	id, err := s.putOvpnTicket("alice", "client.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	tok := do(s, httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?token="+id, nil))
	if tok.Code != http.StatusNotFound || tok.Header().Get("Ovpn-WebAuth") != "" {
		t.Fatalf("token operator off: %d webauth=%q", tok.Code, tok.Header().Get("Ovpn-WebAuth"))
	}

	s2, st2, dir2 := testServer(t)
	c2 := linkedSession(t, s2, st2, "alice")
	if err := os.WriteFile(filepath.Join(dir2, "users", "alice", "client.ovpn"), []byte("client"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "users", "alice", ovpnTokenSentinel), []byte(""), 0660); err != nil {
		t.Fatal(err)
	}
	probe := do(s2, httptest.NewRequest(http.MethodHead, "/openvpn-api/profile", nil))
	if probe.Header().Get("Ovpn-WebAuth") != ovpnWebAuth {
		t.Fatalf("HEAD user sentinel still probes: %q", probe.Header().Get("Ovpn-WebAuth"))
	}
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c2)
	rr = do(s2, req)
	page = rr.Body.String()
	if rr.Code != http.StatusOK || strings.Contains(page, "openvpn://import-profile/") {
		t.Fatalf("html sentinel: %d %s", rr.Code, page)
	}
	if !strings.Contains(page, "Save") {
		t.Fatalf("html sentinel save: %s", page)
	}
	id, err = s2.putOvpnTicket("alice", "client.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	tok = do(s2, httptest.NewRequest(http.MethodGet, "/openvpn-api/profile?token="+id, nil))
	if tok.Code != http.StatusNotFound {
		t.Fatalf("token sentinel: %d", tok.Code)
	}

	if err := os.WriteFile(filepath.Join(dir2, "users", "alice", "home.ovpn"), []byte("home"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir2, "users", "alice", "client.ovpn")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "users", "alice", "work.ovpn"), []byte("work"), 0660); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/openvpn-api/profile", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(c2)
	rr = do(s2, req)
	page = rr.Body.String()
	if strings.Contains(page, "openvpn://import-profile/") {
		t.Fatalf("picker sentinel minted: %s", page)
	}
	if !strings.Contains(page, "profile=work.ovpn") || !strings.Contains(page, "profile=home.ovpn") {
		t.Fatalf("picker sentinel downloads: %s", page)
	}
}

func TestListingShowsDeleteWhenWritable(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "a.txt"), []byte("x"), 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `name="delete"`) {
		t.Fatalf("home listing: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOvpnTicketExpires(t *testing.T) {
	s, _, _ := testServer(t)
	id, err := s.putOvpnTicket("alice", "client.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	s.ovpnMu.Lock()
	got := s.ovpnTickets[id]
	s.ovpnMu.Unlock()
	if d := time.Until(got.exp); d < 50*time.Second || d > 70*time.Second {
		t.Fatalf("ttl remaining %s want ~%s", d, ovpnTicketTTL)
	}
	s.ovpnMu.Lock()
	got.exp = time.Now().Add(-time.Second)
	s.ovpnTickets[id] = got
	s.ovpnMu.Unlock()
	if _, ok := s.peekOvpnTicket(id); ok {
		t.Fatal("peek expired")
	}
}

func hasOvpnTitle(body, title, payload string) bool {
	return strings.Contains(body, "# OVPN_ACCESS_SERVER_FRIENDLY_NAME="+title) &&
		strings.Contains(body, `setenv FRIENDLY_NAME "`+title+`"`) &&
		strings.Contains(body, payload)
}

func ovpnImportHTTPS(page string) []string {
	const prefix = "openvpn://import-profile/"
	var out []string
	rest := page
	for {
		i := strings.Index(rest, prefix)
		if i < 0 {
			return out
		}
		rest = rest[i+len(prefix):]
		href := rest
		if j := strings.Index(href, `"`); j >= 0 {
			href = href[:j]
			rest = rest[j:]
		}
		out = append(out, href)
		if href == rest {
			return out
		}
	}
}
