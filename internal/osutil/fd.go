// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package osutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// Fchmod sets mode on fd (does not follow a path). Logs when Unix bits change.
func Fchmod(fd int, path string, mode os.FileMode) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	from := st.Mode & 0o7777
	to := UnixBits(mode)
	if from == to {
		return nil
	}
	if err := unix.Fchmod(fd, to); err != nil {
		return err
	}
	NoteUnixChmod(path, from, to)
	return nil
}

// Fchown sets uid/gid on fd. -1 means leave that id. Logs when ids change.
func Fchown(fd int, path string, uid, gid int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	ou, og := int(st.Uid), int(st.Gid)
	nu, ng := ou, og
	if uid >= 0 {
		nu = uid
	}
	if gid >= 0 {
		ng = gid
	}
	if nu == ou && ng == og {
		return nil
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	NoteChown(path, ou, og, nu, ng)
	return nil
}
