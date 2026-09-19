// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
	"golang.org/x/sys/unix"
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
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	nonce, err := randomHex(16)
	if err != nil {
		s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	txID, err := randomHex(32)
	if err != nil {
		s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	state, err := s.signState(nonce)
	if err != nil {
		s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	u, verifier, err := s.idp.AuthCodeURL(r.Context(), state, nonce, s.redirectURI())
	if err != nil {
		log.Printf("oidc auth url: %v", err)
		s.loginFail(w, http.StatusBadGateway, "Google is unavailable. Try again.")
		return
	}
	if err := s.putOauthTx(txID, nonce, verifier, time.Now().Add(oauthTTL)); err != nil {
		log.Printf("login oauth tx full from %s", r.RemoteAddr)
		s.loginFail(w, http.StatusServiceUnavailable, "Too many sign-in attempts. Try again.")
		return
	}
	s.setCookie(w, s.oauthCookieName(), txID, int(oauthTTL.Seconds()))
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
		s.loginFail(w, http.StatusBadRequest, "Sign-in was cancelled or failed.")
		return
	}
	c, err := r.Cookie(s.oauthCookieName())
	if err != nil || c.Value == "" {
		log.Printf("login missing oauth cookie from %s", r.RemoteAddr)
		s.loginFail(w, http.StatusBadRequest, "Sign-in expired. Try again.")
		return
	}
	nonce, err := s.verifyState(r.URL.Query().Get("state"))
	if err != nil {
		log.Printf("login invalid state from %s", r.RemoteAddr)
		s.loginFail(w, http.StatusBadRequest, "Sign-in expired. Try again.")
		return
	}
	got, verifier, err := s.takeOauthTx(c.Value)
	if err != nil || got != nonce {
		log.Printf("login oauth tx mismatch from %s", r.RemoteAddr)
		s.loginFail(w, http.StatusBadRequest, "Sign-in expired. Try again.")
		return
	}
	s.setCookie(w, s.oauthCookieName(), "", -1)
	id, err := s.idp.Exchange(r.Context(), r.URL.Query().Get("code"), nonce, s.redirectURI(), verifier)
	if err != nil {
		log.Printf("oidc exchange: %v", err)
		s.loginFail(w, http.StatusBadRequest, "Sign-in failed. Try again.")
		return
	}
	sess, err := s.store.CreateSession(id.Issuer, id.Subject, id.Email, sessionTTL)
	if err != nil {
		log.Printf("login session: %v", err)
		s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
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
		s.render(w, "link", sessionPage(sess, pageData{Title: "Link account", Hint: hintUsername(sess.Email)}))
	case http.MethodPost:
		if !s.requireCSRF(w, r) {
			return
		}
		_ = r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		if s.pam == nil {
			s.replyError(w, r, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		if err := s.pam.Authenticate(user, pass); err != nil {
			log.Printf("link denied pam=%s sub=%s from %s", user, sess.Sub, r.RemoteAddr)
			s.render(w, "link", sessionPage(sess, pageData{Title: "Link account", Error: "username or password not accepted", Hint: user}))
			return
		}
		acct, err := pamauth.Lookup(user)
		if err != nil {
			log.Printf("link unknown user=%s sub=%s from %s", user, sess.Sub, r.RemoteAddr)
			s.render(w, "link", sessionPage(sess, pageData{Title: "Link account", Error: "unknown local user", Hint: user}))
			return
		}
		if !pamauth.Linkable(acct) {
			log.Printf("link denied pam=%s sub=%s from %s (uid 0)", user, sess.Sub, r.RemoteAddr)
			s.render(w, "link", sessionPage(sess, pageData{Title: "Link account", Error: "username or password not accepted", Hint: user}))
			return
		}
		if err := s.ensureUserDir(user); err != nil {
			log.Printf("user dir: %v", err)
		}
		if err := s.store.SaveLinkedSession(sess, user); err != nil {
			log.Printf("link store pam=%s sub=%s: %v", user, sess.Sub, err)
			s.replyError(w, r, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		s.setSessionCookie(w, sess)
		log.Printf("link ok pam=%s sub=%s email=%s from %s", user, sess.Sub, sess.Email, r.RemoteAddr)
		http.Redirect(w, r, "/home/", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	sess := s.session(r)
	if sess != nil {
		pam := sess.PAMUser
		_ = s.store.DeleteSession(sess.ID)
		log.Printf("logout pam=%s sub=%s from %s", pam, sess.Sub, r.RemoteAddr)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// fixCubbies reapplies 2770 user:bootstash on existing cubbies and
// linked PAM names. Same caps as /link (CAP_CHOWN / CAP_FSETID /
// CAP_FOWNER); not limited to link time.
func (s *Server) fixCubbies() {
	names := make(map[string]struct{})
	users := s.usersDir()
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
		s.fixCubbyTree(filepath.Join(s.usersDir(), n))
	}
}

func (s *Server) usersDir() string {
	return filepath.Join(filepath.Clean(s.config().Data), "users")
}

func (s *Server) ensureUserDir(pamUser string) error {
	if !pamauth.ValidUsername(pamUser) {
		return os.ErrNotExist
	}
	users := s.usersDir()
	dir := filepath.Join(users, pamUser)
	if _, err := osutil.Confine(users, dir); err != nil {
		return os.ErrNotExist
	}
	acct, err := pamauth.Lookup(pamUser)
	if err == nil && !pamauth.Linkable(acct) {
		return pamauth.ErrDenied
	}
	usersfd, oerr := openDir(users)
	if oerr != nil {
		return oerr
	}
	defer unix.Close(usersfd)
	if merr := unix.Mkdirat(usersfd, pamUser, 0770); merr != nil && merr != syscall.EEXIST {
		return merr
	}
	fd, oerr := unix.Openat(usersfd, pamUser, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if oerr != nil {
		return oerr
	}
	defer unix.Close(fd)
	if err != nil {
		return cubbyModeFD(fd, dir)
	}
	gid := acct.GID
	if g := s.unixGid(); g >= 0 {
		gid = g
	}
	if cerr := osutil.Fchown(fd, dir, acct.UID, gid); cerr != nil {
		log.Printf("chown %s: %v", dir, cerr)
	}
	return cubbyModeFD(fd, dir)
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
	users := s.usersDir()
	cubby := filepath.Join(users, pamUser)
	if _, err := osutil.Confine(users, cubby); err != nil {
		return
	}
	gid := s.unixGid()
	usersfd, err := openDir(users)
	if err != nil {
		return
	}
	defer unix.Close(usersfd)
	fd, err := unix.Openat(usersfd, pamUser, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	acc := cubby
	if rel != "" && rel != "." {
		if !filepath.IsLocal(rel) {
			unix.Close(fd)
			return
		}
		for _, p := range strings.Split(rel, "/") {
			if p == "" || p == "." {
				continue
			}
			if !filepath.IsLocal(p) {
				unix.Close(fd)
				return
			}
			next := filepath.Join(acc, p)
			if _, err := osutil.Confine(users, next); err != nil {
				unix.Close(fd)
				return
			}
			nfd, oerr := unix.Openat(fd, p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(fd)
			if oerr != nil {
				return
			}
			fd = nfd
			acc = next
			s.fixCubbyFD(fd, acc, gid)
		}
	} else {
		s.fixCubbyFD(fd, acc, gid)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return
	}
	s.fixCubbyDirChildren(fd, acc, users, gid)
	unix.Close(fd)
}

func cubbyModeFD(fd int, path string) error {
	// Unix 02770. os.Chmod(02770) does not set setgid: Go FileMode
	// setgid is ModeSetgid, not the 02000 bit.
	return osutil.Fchmod(fd, path, os.ModeSetgid|0770)
}

func openDir(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// fixCubbyTree walks a cubby (start/SIGHUP). Per-request reads use
// prepareCubbyRead instead.
func (s *Server) fixCubbyTree(root string) {
	users := s.usersDir()
	rel, err := filepath.Rel(users, filepath.Clean(root))
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return
	}
	gid := s.unixGid()
	usersfd, err := openDir(users)
	if err != nil {
		return
	}
	defer unix.Close(usersfd)
	fd, err := unix.Openat(usersfd, rel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	s.fixCubbyFD(fd, filepath.Join(users, rel), gid)
	s.fixCubbyDirChildren(fd, filepath.Join(users, rel), users, gid)
}

func (s *Server) fixCubbyDirChildren(dirfd int, path, users string, gid int) {
	dup, err := unix.FcntlInt(uintptr(dirfd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(dup), path)
	ents, err := f.ReadDir(0)
	f.Close()
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		if !filepath.IsLocal(name) {
			continue
		}
		child := filepath.Join(path, name)
		if _, err := osutil.Confine(users, child); err != nil {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if e.IsDir() {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(dirfd, name, flags, 0)
		if err != nil {
			continue
		}
		if e.IsDir() {
			s.fixCubbyFD(fd, child, gid)
			s.fixCubbyDirChildren(fd, child, users, gid)
		} else {
			s.fixCubbyFD(fd, child, gid)
		}
		unix.Close(fd)
	}
}

func (s *Server) fixCubbyFD(fd int, path string, gid int) {
	path, err := osutil.Confine(s.usersDir(), filepath.Clean(path))
	if err != nil {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if err := cubbyModeFD(fd, path); err != nil {
			log.Printf("cubby dir %s: %v", path, err)
		}
	case unix.S_IFREG:
		if gid >= 0 {
			if err := osutil.Fchown(fd, path, -1, gid); err != nil {
				log.Printf("chown %s: %v", path, err)
			}
		}
		perm := st.Mode & 0o777
		want := (perm | 0o040) &^ 0o007
		if perm&0o100 != 0 {
			want |= 0o010
		}
		if err := osutil.Fchmod(fd, path, os.FileMode(want)); err != nil {
			log.Printf("cubby file %s: %v", path, err)
		}
	}
}

func hintUsername(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return ""
}
