// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package osutil

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Confine returns a cleaned path that is root or a descendant of root.
func Confine(root, path string) (string, error) {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path != root && !strings.HasPrefix(path, root+string(filepath.Separator)) {
		return "", os.ErrInvalid
	}
	return path, nil
}

// Fchmod sets mode on fd (does not follow a path). Logs when Unix bits change.
func Fchmod(fd int, path string, mode os.FileMode) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	// Stat_t.Mode is uint32 on Linux and uint16 on Darwin.
	from := uint32(st.Mode) & 0o7777
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

// Chmod sets mode. Logs when the Unix permission bits actually change.
func Chmod(path string, mode os.FileMode) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	from := UnixBits(st.Mode())
	to := UnixBits(mode)
	if from == to {
		return nil
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	log.Printf("chmod %s %04o -> %04o", path, from, to)
	return nil
}

// NoteChmod logs a mode change that already happened (or is about to
// match `to`). No-op if bits are equal.
func NoteChmod(path string, from, to os.FileMode) {
	NoteUnixChmod(path, UnixBits(from), UnixBits(to))
}

// NoteUnixChmod logs a chmod using Unix 07777 bits.
func NoteUnixChmod(path string, from, to uint32) {
	from &= 0o7777
	to &= 0o7777
	if from == to {
		return
	}
	log.Printf("chmod %s %04o -> %04o", path, from, to)
}

// UnixBits is the Unix 07777 permission bits of a Go FileMode
// (setuid/setgid/sticky plus 0777). os.FileMode(02770) is not Unix 02770.
func UnixBits(m os.FileMode) uint32 {
	u := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		u |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		u |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		u |= 0o1000
	}
	return u
}
