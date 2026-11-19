// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.nyet.org/bootstash/internal/config"
	"go.nyet.org/bootstash/internal/oidcgoogle"
	"go.nyet.org/bootstash/internal/osutil"
	"go.nyet.org/bootstash/internal/store"
	"golang.org/x/sys/unix"
)

// errLoginDenied is a login rejection with no session cookie.
var errLoginDenied = errors.New("login denied")

func (s *Server) homeDir() string {
	return filepath.Join(filepath.Clean(s.config().Data), "home")
}

func validCubbyID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// gateIdentity decides whether this OIDC identity may receive a session.
// A non-empty allowlist requires a verified listed address and pins
// (issuer, sub). PAM=yes with an empty list admits the provider login;
// Unix link is still required before /home. PAM=no with an empty list
// admits a verified address only when home/<id> already exists (put
// -email creates it), then pins (issuer, sub) the same way. A subject
// already linked to a Unix user is admitted without that directory.
func (s *Server) gateIdentity(id *oidcgoogle.Identity) error {
	if id == nil {
		return errLoginDenied
	}
	cfg := s.config()
	email, emailErr := config.NormalizeEmail(id.Email)
	verified := id.EmailVerified && emailErr == nil
	if len(cfg.AllowedEmails) > 0 {
		if !verified || !cfg.AllowsEmail(email) {
			return errLoginDenied
		}
		return s.pinSubject(email, id)
	}
	if cfg.PAM {
		return nil
	}
	pam, ok, err := s.store.LookupLink(id.Issuer, id.Subject)
	if err != nil {
		return err
	}
	if ok && pam != "" {
		return nil
	}
	if !verified {
		return errLoginDenied
	}
	cubbyID, err := config.EmailCubbyID(email)
	if err != nil || !s.emailCubbyOK(cubbyID) {
		return errLoginDenied
	}
	return s.pinSubject(email, id)
}

func (s *Server) pinSubject(email string, id *oidcgoogle.Identity) error {
	if err := s.store.BindSubject(email, id.Issuer, id.Subject); err != nil {
		if errors.Is(err, store.ErrSubjectMismatch) {
			return errLoginDenied
		}
		return err
	}
	return nil
}

// sessionHasCubby is true when this session may open /home.
// A PAM user uses users/<pam>. Otherwise PAM=no uses the
// session's own email hash.
func (s *Server) sessionHasCubby(sess *store.Session) bool {
	if sess == nil {
		return false
	}
	if sess.PAMUser != "" {
		return true
	}
	_, ok := s.emailHomeID(sess)
	return ok
}

// emailHomeID is the cubby directory name for an unlinked session when
// PAM link is not required. A non-empty allowlist is checked again here.
func (s *Server) emailHomeID(sess *store.Session) (string, bool) {
	if sess == nil || sess.PAMUser != "" || s.config().PAM {
		return "", false
	}
	id, err := config.EmailCubbyID(sess.Email)
	if err != nil {
		return "", false
	}
	if len(s.config().AllowedEmails) > 0 && !s.config().AllowsEmail(sess.Email) {
		return "", false
	}
	return id, true
}

func (s *Server) prepareEmailCubby(id, rel string) {
	if !validCubbyID(id) {
		return
	}
	s.prepareExistingCubby(s.homeDir(), id, rel)
}

// emailCubbyOK reports whether home/<id> is a real directory. A symlink
// is refused so OpenRoot does not follow it.
func (s *Server) emailCubbyOK(id string) bool {
	if !validCubbyID(id) {
		return false
	}
	st, err := os.Lstat(filepath.Join(s.homeDir(), id))
	return err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0
}

// fixEmailCubbies repairs mode and group on existing email cubbies.
// It does not create them and does not change the owner uid.
func (s *Server) fixEmailCubbies() {
	home := s.homeDir()
	ents, err := os.ReadDir(home)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("home/: %v", err)
		}
		return
	}
	for _, e := range ents {
		if !e.IsDir() || !validCubbyID(e.Name()) {
			continue
		}
		s.prepareExistingCubby(home, e.Name(), "")
	}
}

// prepareExistingCubby fixes the cubby root, the path about to be read,
// and (for a directory) its immediate children. It does not create the
// cubby and does not change the owner uid.
func (s *Server) prepareExistingCubby(parent, name, rel string) {
	cubby := filepath.Join(parent, name)
	if _, err := osutil.Confine(parent, cubby); err != nil {
		return
	}
	st, err := os.Lstat(cubby)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return
	}
	gid := s.unixGid()
	parentfd, err := openDir(parent)
	if err != nil {
		return
	}
	defer unix.Close(parentfd)
	fd, err := unix.Openat(parentfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
			if _, err := osutil.Confine(parent, next); err != nil {
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
			s.fixCubbyFD(fd, acc, parent, gid)
		}
	} else {
		s.fixCubbyFD(fd, acc, parent, gid)
	}
	var stt unix.Stat_t
	if err := unix.Fstat(fd, &stt); err != nil || stt.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return
	}
	s.fixCubbyDirChildren(fd, acc, parent, gid)
	unix.Close(fd)
}
