// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package store keeps sessions and OIDC-to-PAM links under $DATA/state.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nyet/bootstash/internal/osutil"
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
	return &Store{dir: dir}, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// EnsureCryptoKey loads or creates a 32-byte key used for OIDC state HMAC.
func (s *Store) EnsureCryptoKey(existing []byte) ([]byte, error) {
	if len(existing) >= 32 {
		return existing, nil
	}
	path := filepath.Join(s.dir, "crypto.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return nil, err
	}
	return b, nil
}

// CreateSession stores a new session and returns it.
func (s *Store) CreateSession(iss, sub, email string, ttl time.Duration) (*Session, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:      id,
		Iss:     iss,
		Sub:     sub,
		Email:   email,
		Expires: time.Now().Add(ttl),
	}
	if pam, ok, err := s.LookupLink(iss, sub); err != nil {
		return nil, err
	} else if ok {
		sess.PAMUser = pam
	}
	if err := s.saveSession(sess); err != nil {
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
	return s.saveSession(sess)
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
	return os.WriteFile(path, b, 0600)
}

func (s *Store) sessionPath(id string) (string, bool) {
	if !safeID(id) || !filepath.IsLocal(id) {
		return "", false
	}
	return filepath.Join(s.dir, "sessions-"+id+".json"), true
}

// LookupLink returns the PAM user for an OIDC subject.
func (s *Store) LookupLink(iss, sub string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// LinkedPAMUsers returns distinct PAM names from the link table.
func (s *Store) LinkedPAMUsers() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lf, err := s.readLinks()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var out []string
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
	return out, nil
}

// SetLink stores (iss,sub) -> pamUser. The subject maps to at most one user.
func (s *Store) SetLink(iss, sub, pamUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// DeleteLink removes a subject mapping.
func (s *Store) DeleteLink(iss, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lf, err := s.readLinks()
	if err != nil {
		return err
	}
	out := lf.Links[:0]
	for _, l := range lf.Links {
		if l.Issuer == iss && l.Subject == sub {
			continue
		}
		out = append(out, l)
	}
	lf.Links = out
	return s.writeLinks(lf)
}

func (s *Store) readLinks() (*linkFile, error) {
	b, err := os.ReadFile(s.linksPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &linkFile{}, nil
		}
		return nil, err
	}
	var lf linkFile
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, err
	}
	return &lf, nil
}

func (s *Store) writeLinks(lf *linkFile) error {
	b, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.linksPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.linksPath())
}

func (s *Store) linksPath() string {
	return filepath.Join(s.dir, "links.json")
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
