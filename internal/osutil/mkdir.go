// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package osutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// ChownError is a failed owner or group change after the directory
// exists. The mode has already been set to 02770.
type ChownError struct {
	Path string
	Err  error
}

func (e *ChownError) Error() string {
	return fmt.Sprintf("chown %s: %v", e.Path, e.Err)
}

func (e *ChownError) Unwrap() error { return e.Err }

// MkdirOwner creates or repairs parent/name as mode 02770.
// uid >= 0 chowns it to uid:gid. gid < 0 leaves the group.
// A symlink is refused. name must stay inside parent.
func MkdirOwner(parent, name string, uid, gid int) error {
	dir := filepath.Join(parent, name)
	if _, err := Confine(parent, dir); err != nil {
		return os.ErrNotExist
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Mkdirat(fd, name, 0770); err != nil && err != syscall.EEXIST {
		return err
	}
	child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(child)
	var chownErr error
	if uid >= 0 {
		chownErr = Fchown(child, dir, uid, gid)
	}
	// Unix 02770. os.Chmod(02770) does not set setgid: Go FileMode
	// setgid is ModeSetgid, not the 02000 bit.
	if err := Fchmod(child, dir, os.ModeSetgid|0770); err != nil {
		return err
	}
	if chownErr != nil {
		return &ChownError{Path: dir, Err: chownErr}
	}
	return nil
}
