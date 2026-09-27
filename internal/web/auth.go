// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
	"golang.org/x/sys/unix"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleLoginGet(w, r)
	case http.MethodPost:
		s.handleLoginPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess != nil && s.sessionHasCubby(sess) {
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	name := r.URL.Query().Get("provider")
	if name == "" || s.passwordLogin(sess) {
		if name != "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		s.render(w, "login", s.loginPage(sess))
		return
	}
	idp, ok := s.activeIDP(name)
	if !ok {
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
	u, verifier, err := idp.AuthCodeURL(r.Context(), state, nonce, s.redirectURI())
	if err != nil {
		log.Printf("oidc auth url provider=%s: %v", name, err)
		s.loginFail(w, http.StatusBadGateway, "Sign-in is unavailable. Try again.")
		return
	}
	if err := s.putOauthTx(txID, name, nonce, verifier, time.Now().Add(oauthTTL)); err != nil {
		log.Printf("login oauth tx full from %s", r.RemoteAddr)
		s.loginFail(w, http.StatusServiceUnavailable, "Too many sign-in attempts. Try again.")
		return
	}
	s.setCookie(w, s.oauthCookieName(), txID, int(oauthTTL.Seconds()))
	log.Printf("login start provider=%s from %s", name, r.RemoteAddr)
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if !s.passwordLogin(sess) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	_ = r.ParseForm()
	user := strings.TrimSpace(r.FormValue("username"))
	acct, err := s.acceptLocalUser(user, r.FormValue("password"))
	if err != nil {
		sub := ""
		if sess != nil {
			sub = sess.Sub
		}
		log.Printf("login denied pam=%s sub=%s from %s", user, sub, r.RemoteAddr)
		if !errors.Is(err, pamauth.ErrDenied) && !errors.Is(err, errUnknownUser) {
			s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		data := s.loginPage(sess)
		data.Error = "username or password not accepted"
		if errors.Is(err, errUnknownUser) {
			data.Error = "unknown local user"
		}
		data.Hint = user
		s.render(w, "login", data)
		return
	}
	if err := s.ensureUserDir(acct.Name); err != nil {
		log.Printf("user dir: %v", err)
	}
	var out *store.Session
	if sess == nil {
		created, err := s.store.CreatePAMSession(acct.Name, sessionTTL)
		if err != nil {
			log.Printf("login session pam=%s: %v", acct.Name, err)
			s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		out = created
		log.Printf("login pam=%s from %s", acct.Name, r.RemoteAddr)
	} else {
		if err := s.store.SaveLinkedSession(sess, acct.Name); err != nil {
			log.Printf("login store pam=%s sub=%s: %v", acct.Name, sess.Sub, err)
			s.replyError(w, r, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		out = sess
		log.Printf("login pam=%s sub=%s email=%s from %s", acct.Name, sess.Sub, sess.Email, r.RemoteAddr)
	}
	s.setSessionCookie(w, out)
	http.Redirect(w, r, s.afterLogin(r, true), http.StatusFound)
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
	got, provider, verifier, err := s.takeOauthTx(c.Value)
	if err != nil || got != nonce {
		log.Printf("login oauth tx mismatch from %s", r.RemoteAddr)
		s.loginFail(w, http.StatusBadRequest, "Sign-in expired. Try again.")
		return
	}
	s.setCookie(w, s.oauthCookieName(), "", -1)
	idp, ok := s.activeIDP(provider)
	if !ok {
		log.Printf("login unknown provider %q from %s", provider, r.RemoteAddr)
		s.loginFail(w, http.StatusBadRequest, "Sign-in expired. Try again.")
		return
	}
	id, err := idp.Exchange(r.Context(), r.URL.Query().Get("code"), nonce, s.redirectURI(), verifier)
	if err != nil {
		log.Printf("oidc exchange: %v", err)
		s.loginFail(w, http.StatusBadRequest, "Sign-in failed. Try again.")
		return
	}
	if err := s.gateIdentity(id); err != nil {
		if errors.Is(err, errLoginDenied) {
			log.Printf("login rejected email=%s verified=%v sub=%s from %s", id.Email, id.EmailVerified, id.Subject, r.RemoteAddr)
			s.loginFail(w, http.StatusForbidden, "This account is not allowed to sign in.")
			return
		}
		log.Printf("login gate: %v", err)
		s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	email := id.Email
	if n, nerr := config.NormalizeEmail(id.Email); nerr == nil {
		email = n
	}
	sess, err := s.store.CreateSession(id.Issuer, id.Subject, email, sessionTTL)
	if err != nil {
		log.Printf("login session: %v", err)
		s.loginFail(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	s.setSessionCookie(w, sess)
	if !s.sessionHasCubby(sess) {
		log.Printf("login oidc sub=%s email=%s from %s (unlinked)", id.Subject, id.Email, r.RemoteAddr)
		http.Redirect(w, r, s.afterLogin(r, false), http.StatusFound)
		return
	}
	log.Printf("login oidc sub=%s email=%s pam=%s from %s", id.Subject, id.Email, sess.PAMUser, r.RemoteAddr)
	http.Redirect(w, r, s.afterLogin(r, true), http.StatusFound)
}

var errUnknownUser = errors.New("unknown local user")

// acceptLocalUser checks the PAM helper and resolves a linkable Unix account.
// UID 0 is ErrDenied. A missing passwd entry is errUnknownUser.
func (s *Server) acceptLocalUser(user, pass string) (*pamauth.Account, error) {
	if s.pam == nil {
		return nil, errors.New("pam authenticator is not configured")
	}
	if err := s.pam.Authenticate(user, pass); err != nil {
		return nil, pamauth.ErrDenied
	}
	acct, err := pamauth.Lookup(user)
	if err != nil {
		return nil, errUnknownUser
	}
	if !pamauth.Linkable(acct) {
		return nil, pamauth.ErrDenied
	}
	return acct, nil
}

// passwordLogin is the Unix password form: PAM-only when there is no
// session, or the password after OIDC auth when the session has no cubby.
func (s *Server) passwordLogin(sess *store.Session) bool {
	if sess != nil && s.sessionHasCubby(sess) {
		return false
	}
	if s.config().PAMLogin() {
		return true
	}
	return sess != nil && s.config().LinkPAM()
}

func (s *Server) loginPage(sess *store.Session) pageData {
	data := pageData{Title: "Sign in"}
	if sess != nil {
		data = sessionPage(sess, data)
	}
	if s.passwordLogin(sess) {
		data.PAMLogin = true
		data.Title = "Log in"
		if data.Hint == "" && sess != nil {
			data.Hint = hintUsername(sess.Email)
		}
		return data
	}
	for _, name := range s.config().Providers() {
		id, ok := s.registered(name)
		if !ok {
			continue
		}
		label := id.Label
		if label == "" {
			label = name
		}
		data.Providers = append(data.Providers, loginChoice{
			Label: label,
			Href:  "/login?provider=" + url.QueryEscape(name),
		})
	}
	return data
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
// linked PAM names. Same caps as login (CAP_CHOWN / CAP_FSETID /
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
		s.prepareExistingCubby(s.usersDir(), n, "")
	}
	s.fixEmailCubbies()
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
	uid, gid := -1, -1
	if err == nil {
		uid = acct.UID
		gid = acct.GID
		if g := s.unixGid(); g >= 0 {
			gid = g
		}
	}
	if err := osutil.MkdirOwner(users, pamUser, uid, gid); err != nil {
		var ce *osutil.ChownError
		if errors.As(err, &ce) {
			log.Printf("%v", ce)
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) unixGid() int {
	g, err := pamauth.LookupGroupGID(s.config().UnixGroup)
	if err != nil {
		return -1
	}
	return g
}

// prepareCubbyRead fixes the PAM cubby root, the path about to be read,
// and (for a directory) its immediate children. Not a full-tree walk.
// It may create users/<pam> and chown that directory to the Unix user.
func (s *Server) prepareCubbyRead(pamUser, rel string) {
	if err := s.ensureUserDir(pamUser); err != nil {
		log.Printf("cubby %s: %v", pamUser, err)
		return
	}
	s.prepareExistingCubby(s.usersDir(), pamUser, rel)
}

func cubbyModeFD(fd int, path string) error {
	// Unix 02770. os.Chmod(02770) does not set setgid: Go FileMode
	// setgid is ModeSetgid, not the 02000 bit.
	return osutil.Fchmod(fd, path, os.ModeSetgid|0770)
}

func openDir(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
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
		s.fixCubbyFD(fd, child, users, gid)
		if e.IsDir() {
			s.fixCubbyDirChildren(fd, child, users, gid)
		}
		unix.Close(fd)
	}
}

func (s *Server) fixCubbyFD(fd int, path, confine string, gid int) {
	path, err := osutil.Confine(confine, filepath.Clean(path))
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
