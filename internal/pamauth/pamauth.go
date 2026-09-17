// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package pamauth authenticates existing Unix users via PAM.
package pamauth

import (
	"errors"
	"os/user"
	"strconv"
	"strings"
	"unicode"
)

// ErrDenied is a failed username/password check.
var ErrDenied = errors.New("pam authentication failed")

// Authenticator checks a local username and password.
type Authenticator interface {
	Authenticate(username, password string) error
}

// Account is a resolved PAM/Unix user.
type Account struct {
	Name string
	UID  int
	GID  int
}

// ValidUsername is a single path component safe to use under $DATA/users/.
func ValidUsername(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\:\x00") {
		return false
	}
	for _, r := range name {
		if r > unicode.MaxASCII {
			return false
		}
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}

// Lookup returns the Unix account for an existing user. It does not create users.
func Lookup(name string) (*Account, error) {
	if !ValidUsername(name) {
		return nil, ErrDenied
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, err
	}
	return &Account{Name: u.Username, UID: uid, GID: gid}, nil
}

// LookupGroupGID returns a group's numeric id.
func LookupGroupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}
