//go:build !cgo || !linux || nopam

// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package pamauth

import "errors"

// errUnavailable is returned when this build does not link libpam.
// macOS OpenPAM has no pam_start_confdir, which github.com/msteinert/pam
// references, so non-Linux builds and -tags nopam leave it out.
var errUnavailable = errors.New("PAM is not available in this build")

type unavailable struct{}

func (unavailable) Authenticate(string, string) error {
	return errUnavailable
}

func inProcess(string) Authenticator {
	return unavailable{}
}

// Run is the setuid helper entry. This build has no libpam.
func Run(string, string, string) error {
	return errUnavailable
}
