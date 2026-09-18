// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package pamauth

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// DefaultHelperPath is the packaged setuid helper (not on PATH).
const DefaultHelperPath = "/usr/lib/bootstash/pam"

const helperTimeout = 30 * time.Second

// Helper execs the setuid PAM binary. Password is stdin, never argv.
type Helper struct {
	Path    string
	Service string
}

// Authenticate runs the helper: pam <service> <username>, password on stdin.
func (h Helper) Authenticate(username, password string) error {
	if !ValidUsername(username) {
		return ErrDenied
	}
	svc := h.Service
	if svc == "" {
		svc = DefaultService
	}
	if !ValidService(svc) {
		return ErrDenied
	}
	path := h.Path
	if path == "" {
		path = DefaultHelperPath
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, svc, username)
	cmd.Stdin = bytes.NewReader([]byte(password))
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
	}
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ErrDenied
	}
	return err
}
