// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package store keeps sessions and OIDC-to-PAM links under $DATA/state.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nyet/bootstash/internal/osutil"
	"golang.org/x/sys/unix"
)

// Session is a server-side login.
type Session struct {
	ID      string    `json:"id"`
	Iss     string    `json:"iss"`
	Sub     string    `json:"sub"`
	PAMUser string    `json:"pam_user,omitempty"`
	Email   string    `json:"email,omitempty"`
	Expires time.Time `json:"expires"`
}

type linkFile struct {
	Links []Link `json:"links"`
}

// Link maps an OIDC subject to a PAM user.
type Link struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"sub"`
	PAMUser string `json:"pam_user"`
}

// Subject pins one verified address to an OIDC (issuer, sub).
type Subject struct {
	Email   string `json:"email"`
	Issuer  string `json:"issuer"`
	Subject string `json:"sub"`
}

type subjectFile struct {
	Subjects []Subject `json:"subjects"`
}

// ErrSubjectMismatch means this address is already pinned to a
// different (issuer, sub). The row is left unchanged.
var ErrSubjectMismatch = errors.New("oidc subject does not match the address")

// Store is a directory-backed session and link table.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open initializes $DATA/state.
func Open(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "state")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := osutil.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	s.reclaimState()
	return s, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// EnsureCryptoKey loads or creates a 32-byte key used for OIDC state HMAC.
func (s *Store) EnsureCryptoKey(existing []byte) ([]byte, error) {
	if len(existing) >= 32 {
		return existing, nil
	}
	var out []byte
	err := s.withLock(func() error {
		path := filepath.Join(s.dir, "crypto.key")
		if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
			out = b
			return nil
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if err := s.writeStateFile(path, b); err != nil {
			return err
		}
		out = b
		return nil
	})
	return out, err
}

// CreateSession stores a new session and returns it.
func (s *Store) CreateSession(iss, sub, email string, ttl time.Duration) (*Session, error) {
	sess := &Session{Iss: iss, Sub: sub, Email: email}
	return s.putSession(sess, ttl, func() error {
		pam, ok, err := s.lookupLinkLocked(iss, sub)
		if err != nil {
			return err
		}
		if ok {
			sess.PAMUser = pam
		}
		return nil
	})
}

// CreatePAMSession stores a session for a Unix user. Issuer and subject
// stay empty, and the link table is not consulted.
func (s *Store) CreatePAMSession(pamUser string, ttl time.Duration) (*Session, error) {
	if pamUser == "" {
		return nil, os.ErrInvalid
	}
	return s.putSession(&Session{PAMUser: pamUser}, ttl, nil)
}

func (s *Store) putSession(sess *Session, ttl time.Duration, prep func() error) (*Session, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	sess.ID = id
	sess.Expires = time.Now().Add(ttl)
	if err := s.withLock(func() error {
		if prep != nil {
			if err := prep(); err != nil {
				return err
			}
		}
		return s.saveSession(sess)
	}); err != nil {
		return nil, err
	}
	return sess, nil
}

// GetSession loads a non-expired session.
func (s *Store) GetSession(id string) (*Session, error) {
	path, ok := s.sessionPath(id)
	if !ok {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, err
	}
	if time.Now().After(sess.Expires) {
		_ = os.Remove(path)
		return nil, os.ErrNotExist
	}
	return &sess, nil
}

// SaveSession writes an existing session (link updates).
func (s *Store) SaveSession(sess *Session) error {
	return s.withLock(func() error {
		return s.saveSession(sess)
	})
}

// DeleteSession removes a session file. Missing is not an error.
func (s *Store) DeleteSession(id string) error {
	path, ok := s.sessionPath(id)
	if !ok {
		return os.ErrNotExist
	}
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *Store) saveSession(sess *Session) error {
	if sess == nil {
		return os.ErrInvalid
	}
	path, ok := s.sessionPath(sess.ID)
	if !ok {
		return os.ErrInvalid
	}
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.writeStateFile(path, b)
}

func (s *Store) sessionPath(id string) (string, bool) {
	if !safeID(id) || !filepath.IsLocal(id) {
		return "", false
	}
	return filepath.Join(s.dir, "sessions-"+id+".json"), true
}

func (s *Store) lockPath() string {
	return filepath.Join(s.dir, ".lock")
}

// withLock is an in-process mutex plus flock so bootstashd and
// bootstash unlink cannot interleave a links.json read-modify-write.
func (s *Store) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	_ = osutil.Chmod(s.lockPath(), 0600)
	_ = s.chownToState(s.lockPath())
	return fn()
}

// LookupLink returns the PAM user for an OIDC subject.
func (s *Store) LookupLink(iss, sub string) (string, bool, error) {
	var pam string
	var ok bool
	err := s.withLock(func() error {
		var err error
		pam, ok, err = s.lookupLinkLocked(iss, sub)
		return err
	})
	return pam, ok, err
}

func (s *Store) lookupLinkLocked(iss, sub string) (string, bool, error) {
	lf, err := s.readLinks()
	if err != nil {
		return "", false, err
	}
	for _, l := range lf.Links {
		if l.Issuer == iss && l.Subject == sub {
			return l.PAMUser, true, nil
		}
	}
	return "", false, nil
}

// ListLinks returns OIDC→PAM mappings. Rows with an empty PAM name are omitted.
func (s *Store) ListLinks() ([]Link, error) {
	var out []Link
	err := s.withLock(func() error {
		lf, err := s.readLinks()
		if err != nil {
			return err
		}
		out = make([]Link, 0, len(lf.Links))
		for _, l := range lf.Links {
			if l.PAMUser == "" {
				continue
			}
			out = append(out, l)
		}
		return nil
	})
	return out, err
}

// LinkedPAMUsers returns distinct PAM names from the link table.
func (s *Store) LinkedPAMUsers() ([]string, error) {
	var out []string
	err := s.withLock(func() error {
		lf, err := s.readLinks()
		if err != nil {
			return err
		}
		seen := make(map[string]struct{})
		for _, l := range lf.Links {
			if l.PAMUser == "" {
				continue
			}
			if _, ok := seen[l.PAMUser]; ok {
				continue
			}
			seen[l.PAMUser] = struct{}{}
			out = append(out, l.PAMUser)
		}
		return nil
	})
	return out, err
}

// SetLink stores (iss,sub) -> pamUser. The subject maps to at most one user.
func (s *Store) SetLink(iss, sub, pamUser string) error {
	return s.withLock(func() error {
		return s.setLinkLocked(iss, sub, pamUser)
	})
}

// SaveLinkedSession writes the link and session together so unlink cannot
// leave a PAM session after dropping the map. The session id is rotated.
// Other sessions for the same (iss, sub) lose PAMUser when the mapping
// changes to a different Unix name.
func (s *Store) SaveLinkedSession(sess *Session, pamUser string) error {
	if sess == nil {
		return os.ErrInvalid
	}
	return s.withLock(func() error {
		prev, _, err := s.lookupLinkLocked(sess.Iss, sess.Sub)
		if err != nil {
			return err
		}
		if err := s.setLinkLocked(sess.Iss, sess.Sub, pamUser); err != nil {
			return err
		}
		old := sess.ID
		id, err := randomID()
		if err != nil {
			return err
		}
		sess.ID = id
		sess.PAMUser = pamUser
		if err := s.saveSession(sess); err != nil {
			sess.ID = old
			return err
		}
		if old != id {
			if path, ok := s.sessionPath(old); ok {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
		if prev != "" && prev != pamUser {
			return s.clearSubjectPAMLocked(sess.Iss, sess.Sub, sess.ID)
		}
		return nil
	})
}

func (s *Store) setLinkLocked(iss, sub, pamUser string) error {
	lf, err := s.readLinks()
	if err != nil {
		return err
	}
	found := false
	for i, l := range lf.Links {
		if l.Issuer == iss && l.Subject == sub {
			lf.Links[i].PAMUser = pamUser
			found = true
			break
		}
	}
	if !found {
		lf.Links = append(lf.Links, Link{Issuer: iss, Subject: sub, PAMUser: pamUser})
	}
	return s.writeLinks(lf)
}

// UnlinkPAM drops every (issuer, sub) mapped to pam and clears PAMUser
// on matching sessions. The cubby on disk is left alone.
func (s *Store) UnlinkPAM(pam string) ([]Link, int, error) {
	if pam == "" {
		return nil, 0, os.ErrInvalid
	}
	var removed []Link
	var n int
	err := s.withLock(func() error {
		lf, err := s.readLinks()
		if err != nil {
			return err
		}
		removed = nil
		out := lf.Links[:0]
		for _, l := range lf.Links {
			if l.PAMUser == pam {
				removed = append(removed, l)
				continue
			}
			out = append(out, l)
		}
		lf.Links = out
		if err := s.writeLinks(lf); err != nil {
			return err
		}
		n, err = s.clearSessionPAMLocked(pam, removed)
		return err
	})
	return removed, n, err
}

func (s *Store) clearSessionPAMLocked(pam string, links []Link) (int, error) {
	type key struct{ iss, sub string }
	want := make(map[key]struct{}, len(links))
	for _, l := range links {
		want[key{l.Issuer, l.Subject}] = struct{}{}
	}
	return s.clearMatchingSessionsLocked(func(sess *Session) bool {
		_, subj := want[key{sess.Iss, sess.Sub}]
		return (sess.PAMUser == pam || subj) && sess.PAMUser != ""
	})
}

func (s *Store) clearSubjectPAMLocked(iss, sub, exceptID string) error {
	_, err := s.clearMatchingSessionsLocked(func(sess *Session) bool {
		return sess.ID != exceptID && sess.Iss == iss && sess.Sub == sub && sess.PAMUser != ""
	})
	return err
}

// clearMatchingSessionsLocked clears PAMUser on each sessions-*.json
// for which match returns true. n is how many were cleared, including
// when a later file fails.
func (s *Store) clearMatchingSessionsLocked(match func(*Session) bool) (int, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "sessions-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			return n, err
		}
		var sess Session
		if err := json.Unmarshal(b, &sess); err != nil {
			return n, fmt.Errorf("session %s: %w", name, err)
		}
		if !match(&sess) {
			continue
		}
		sess.PAMUser = ""
		if err := s.saveSession(&sess); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Store) readLinks() (*linkFile, error) {
	return readJSON[linkFile](s.linksPath())
}

func (s *Store) writeLinks(lf *linkFile) error {
	return s.writeJSON(s.linksPath(), lf)
}

func (s *Store) writeStateFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := osutil.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := s.chownToState(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// reclaimState chowns state files to match the state directory. sudo
// bootstash unlink would otherwise leave links.json as root:root so
// User=bootstash cannot read it.
func (s *Store) reclaimState() {
	st, err := os.Stat(s.dir)
	if err != nil {
		return
	}
	uid, gid, ok := osutil.FileIDs(st)
	if !ok {
		return
	}
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		_ = osutil.Chown(filepath.Join(s.dir, e.Name()), uid, gid)
	}
}

func (s *Store) chownToState(path string) error {
	st, err := os.Stat(s.dir)
	if err != nil {
		return err
	}
	uid, gid, ok := osutil.FileIDs(st)
	if !ok {
		return nil
	}
	return osutil.Chown(path, uid, gid)
}

func (s *Store) linksPath() string {
	return filepath.Join(s.dir, "links.json")
}

func (s *Store) subjectsPath() string {
	return filepath.Join(s.dir, "subjects.json")
}

// BindSubject inserts (email → issuer, sub) on first use. A later
// call for the same email must present that subject. A different
// subject returns ErrSubjectMismatch and does not overwrite the row.
// Other addresses are left alone.
func (s *Store) BindSubject(email, iss, sub string) error {
	if email == "" || iss == "" || sub == "" {
		return os.ErrInvalid
	}
	return s.withLock(func() error {
		sf, err := s.readSubjects()
		if err != nil {
			return err
		}
		for _, row := range sf.Subjects {
			if row.Email != email {
				continue
			}
			if row.Issuer == iss && row.Subject == sub {
				return nil
			}
			return ErrSubjectMismatch
		}
		sf.Subjects = append(sf.Subjects, Subject{Email: email, Issuer: iss, Subject: sub})
		return s.writeSubjects(sf)
	})
}

func (s *Store) readSubjects() (*subjectFile, error) {
	return readJSON[subjectFile](s.subjectsPath())
}

func (s *Store) writeSubjects(sf *subjectFile) error {
	return s.writeJSON(s.subjectsPath(), sf)
}

func readJSON[T any](path string) (*T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return new(T), nil
		}
		return nil, err
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.writeStateFile(path, b)
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func safeID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
