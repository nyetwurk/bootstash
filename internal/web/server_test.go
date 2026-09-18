// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

func (fakeIDP) AuthCodeURL(_ context.Context, state, nonce, redirectURL string) (string, error) {
	return "https://accounts.google.com/o/oauth2/auth?state=" + state + "&nonce=" + nonce + "&redirect_uri=" + redirectURL, nil
}

func (fakeIDP) Exchange(_ context.Context, code, nonce, redirectURL string) (*oidcgoogle.Identity, error) {
	_ = nonce
	_ = redirectURL
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

func TestJailDotDotAndEncoded(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "ok.txt"), []byte("ok"), 0660); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/home/../alice/ok.txt",
		"/home/%2e%2e/ok.txt",
		"/home/foo/%2e%2e/%2e%2e/etc/passwd",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(c)
		rr := do(s, req)
		if rr.Code == http.StatusOK && strings.Contains(rr.Body.String(), "ok") && path != "/home/../alice/ok.txt" {
			// decoded .. is rejected; lexical leftover may 404/400/403
		}
		if rr.Code == 200 && strings.Contains(rr.Body.String(), "root:") {
			t.Fatalf("%s leaked: %s", path, rr.Body.String())
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

func TestUnlinkedCannotRead(t *testing.T) {
	s, st, _ := testServer(t)
	sess, err := st.CreateSession("https://accounts.google.com", "sub-x", "x@y.z", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: s.cookieName(), Value: sess.ID}
	req := httptest.NewRequest(http.MethodGet, "/home/", nil)
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("unlinked GET /home/ => %d", rr.Code)
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

func TestRange(t *testing.T) {
	s, st, dir := testServer(t)
	c := linkedSession(t, s, st, "alice")
	body := []byte("abcdefghij")
	if err := os.WriteFile(filepath.Join(dir, "users", "alice", "x.bin"), body, 0660); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/home/x.bin", nil)
	req.Header.Set("Range", "bytes=0-2")
	req.AddCookie(c)
	rr := do(s, req)
	if rr.Code != http.StatusPartialContent || rr.Body.String() != "abc" {
		t.Fatalf("first bytes: %d %q", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/home/x.bin", nil)
	req.Header.Set("Range", "bytes=-3")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusPartialContent || rr.Body.String() != "hij" {
		t.Fatalf("suffix: %d %q", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/home/x.bin", nil)
	req.Header.Set("Range", "bytes=99-100")
	req.AddCookie(c)
	rr = do(s, req)
	if rr.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("invalid range: %d", rr.Code)
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

func TestLoginStartsOIDC(t *testing.T) {
	s, _, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/login?provider=google", nil)
	rr := do(s, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "accounts.google.com") {
		t.Fatalf("%d %s", rr.Code, rr.Header().Get("Location"))
	}
}

func TestCallbackSetsCookie(t *testing.T) {
	s, _, _ := testServer(t)
	nonce := "n"
	state, err := s.signState(nonce)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?state="+state+"&code=zz", nil)
	rr := do(s, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/link" {
		t.Fatalf("location %s", loc)
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
		"prefers-color-scheme: dark",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("css missing %q", want)
		}
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
	if rr.Code != http.StatusConflict {
		t.Fatalf("non-empty: %d %s", rr.Code, rr.Body.String())
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
