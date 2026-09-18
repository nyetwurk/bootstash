// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("provider") == "" {
		s.render(w, "login", pageData{Title: "Sign in"})
		return
	}
	if r.URL.Query().Get("provider") != "google" {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	nonce, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := s.signState(nonce)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	u, err := s.idp.AuthCodeURL(r.Context(), state, nonce, s.redirectURI())
	if err != nil {
		log.Printf("oidc auth url: %v", err)
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	log.Printf("login start google from %s", r.RemoteAddr)
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		log.Printf("login oidc error from %s: %s", r.RemoteAddr, errMsg)
		http.Error(w, "oidc error: "+errMsg, http.StatusBadRequest)
		return
	}
	nonce, err := s.verifyState(r.URL.Query().Get("state"))
	if err != nil {
		log.Printf("login invalid state from %s", r.RemoteAddr)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	id, err := s.idp.Exchange(r.Context(), r.URL.Query().Get("code"), nonce, s.redirectURI())
	if err != nil {
		log.Printf("oidc exchange: %v", err)
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}
	sess, err := s.store.CreateSession(id.Issuer, id.Subject, id.Email, sessionTTL)
	if err != nil {
		log.Printf("login session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, sess)
	if sess.PAMUser == "" {
		log.Printf("login oidc sub=%s email=%s from %s (unlinked)", id.Subject, id.Email, r.RemoteAddr)
		http.Redirect(w, r, "/link", http.StatusFound)
		return
	}
	log.Printf("login oidc sub=%s email=%s pam=%s from %s", id.Subject, id.Email, sess.PAMUser, r.RemoteAddr)
	http.Redirect(w, r, "/home/", http.StatusFound)
}

func (s *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.render(w, "link", pageData{Title: "Link account", Hint: hintUsername(sess.Email)})
	case http.MethodPost:
		if !s.requireCSRF(w, r) {
			return
		}
		_ = r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		if s.pam == nil {
			http.Error(w, "pam unavailable", http.StatusInternalServerError)
			return
		}
		if err := s.pam.Authenticate(user, pass); err != nil {
			log.Printf("link denied pam=%s sub=%s from %s", user, sess.Sub, r.RemoteAddr)
			s.render(w, "link", pageData{Title: "Link account", Error: "username or password not accepted", Hint: user})
			return
		}
		if _, err := pamauth.Lookup(user); err != nil {
			log.Printf("link unknown user=%s sub=%s from %s", user, sess.Sub, r.RemoteAddr)
			s.render(w, "link", pageData{Title: "Link account", Error: "unknown local user", Hint: user})
			return
		}
		if err := s.store.SetLink(sess.Iss, sess.Sub, user); err != nil {
			log.Printf("link store pam=%s sub=%s: %v", user, sess.Sub, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := s.ensureUserDir(user); err != nil {
			log.Printf("user dir: %v", err)
		}
		sess.PAMUser = user
		if err := s.store.SaveSession(sess); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("link ok pam=%s sub=%s email=%s from %s", user, sess.Sub, sess.Email, r.RemoteAddr)
		http.Redirect(w, r, "/home/", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUnlink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	pam := sess.PAMUser
	_ = s.store.DeleteLink(sess.Iss, sess.Sub)
	sess.PAMUser = ""
	_ = s.store.SaveSession(sess)
	log.Printf("unlink pam=%s sub=%s from %s", pam, sess.Sub, r.RemoteAddr)
	http.Redirect(w, r, "/link", http.StatusFound)
}

// fixCubbies reapplies 2770 user:bootstash on existing cubbies and
// linked PAM names. Same caps as /link (CAP_CHOWN / CAP_FSETID /
// CAP_FOWNER); not limited to link time.
func (s *Server) fixCubbies() {
	names := make(map[string]struct{})
	users := filepath.Join(s.config().Data, "users")
	ents, err := os.ReadDir(users)
	if err != nil {
		log.Printf("users/: %v", err)
	} else {
		for _, e := range ents {
			if !e.IsDir() || !pamauth.ValidUsername(e.Name()) {
				continue
			}
			names[e.Name()] = struct{}{}
		}
	}
	if pam, err := s.store.LinkedPAMUsers(); err != nil {
		log.Printf("links: %v", err)
	} else {
		for _, n := range pam {
			if pamauth.ValidUsername(n) {
				names[n] = struct{}{}
			}
		}
	}
	for n := range names {
		if err := s.ensureUserDir(n); err != nil {
			log.Printf("cubby %s: %v", n, err)
			continue
		}
		s.fixCubbyTree(filepath.Join(users, n))
	}
}

func (s *Server) ensureUserDir(pamUser string) error {
	dir := filepath.Join(s.config().Data, "users", pamUser)
	if err := os.MkdirAll(dir, 0770); err != nil {
		return err
	}
	acct, err := pamauth.Lookup(pamUser)
	if err != nil {
		return cubbyMode(dir)
	}
	gid := acct.GID
	if g := s.unixGid(); g >= 0 {
		gid = g
	}
	if err := osutil.Chown(dir, acct.UID, gid); err != nil {
		log.Printf("chown %s: %v", dir, err)
	}
	// After chown the kernel clears setgid unless CAP_FSETID.
	// chmod again so shell cp inherits group bootstash.
	return cubbyMode(dir)
}

func (s *Server) unixGid() int {
	g, err := pamauth.LookupGroupGID(s.config().UnixGroup)
	if err != nil {
		return -1
	}
	return g
}

// prepareCubbyRead fixes the cubby root, the path about to be read,
// and (for a directory) its immediate children. Not a full-tree walk.
func (s *Server) prepareCubbyRead(pamUser, rel string) {
	if err := s.ensureUserDir(pamUser); err != nil {
		log.Printf("cubby %s: %v", pamUser, err)
		return
	}
	cubby := filepath.Join(s.config().Data, "users", pamUser)
	gid := s.unixGid()
	acc := cubby
	for _, p := range strings.Split(rel, "/") {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return
		}
		acc = filepath.Join(acc, p)
		s.fixCubbyEntry(acc, gid)
	}
	st, err := os.Lstat(acc)
	if err != nil || !st.IsDir() {
		return
	}
	ents, err := os.ReadDir(acc)
	if err != nil {
		return
	}
	for _, e := range ents {
		s.fixCubbyEntry(filepath.Join(acc, e.Name()), gid)
	}
}

func cubbyMode(dir string) error {
	// Unix 02770. os.Chmod(02770) does not set setgid: Go FileMode
	// setgid is ModeSetgid, not the 02000 bit.
	return osutil.Chmod(dir, os.ModeSetgid|0770)
}

// fixCubbyTree walks a cubby (start/SIGHUP). Per-request reads use
// prepareCubbyRead instead.
func (s *Server) fixCubbyTree(root string) {
	gid := s.unixGid()
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		s.fixCubbyEntry(path, gid)
		return nil
	})
}

func (s *Server) fixCubbyEntry(path string, gid int) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return
	}
	if info.IsDir() {
		if err := cubbyMode(path); err != nil {
			log.Printf("cubby dir %s: %v", path, err)
		}
		return
	}
	if !info.Mode().IsRegular() {
		return
	}
	if gid >= 0 {
		if err := osutil.Chown(path, -1, gid); err != nil {
			log.Printf("chown %s: %v", path, err)
		}
	}
	perm := info.Mode().Perm()
	want := (perm | 0040) &^ 0007
	if perm&0100 != 0 {
		want |= 0010
	}
	if err := osutil.Chmod(path, want); err != nil {
		log.Printf("cubby file %s: %v", path, err)
	}
}

func hintUsername(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return ""
}
