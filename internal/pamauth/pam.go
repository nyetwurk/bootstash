//go:build cgo && linux && !nopam

// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package pamauth

import (
	"fmt"
	"runtime"

	"github.com/msteinert/pam"
)

// PAM checks passwords using the named PAM service (in-process).
// The daemon uses Helper (setuid) so pam_unix can verify other users.
type PAM struct {
	Service string
}

func inProcess(service string) Authenticator {
	return PAM{Service: service}
}

// Authenticate runs pam_authenticate and pam_acct_mgmt.
func (p PAM) Authenticate(username, password string) error {
	return Run(p.Service, username, password)
}

// Run is pam_authenticate + pam_acct_mgmt. The setuid helper calls this as root.
func Run(service, username, password string) error {
	if !ValidUsername(username) || !ValidService(service) {
		return ErrDenied
	}
	if acct, err := Lookup(username); err == nil && !Linkable(acct) {
		return ErrDenied
	}
	svc := service
	if svc == "" {
		svc = DefaultService
	}
	t, err := pam.StartFunc(svc, username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return password, nil
		case pam.PromptEchoOn:
			return username, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", fmt.Errorf("unsupported PAM conversation: %v %s", s, msg)
		}
	})
	if err != nil {
		return err
	}
	if err := t.Authenticate(0); err != nil {
		return ErrDenied
	}
	if err := t.AcctMgmt(0); err != nil {
		return ErrDenied
	}
	runtime.KeepAlive(t)
	return nil
}
