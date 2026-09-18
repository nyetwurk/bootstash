// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package osutil

import (
	"log"
	"os"
	"syscall"
)

// Chown sets uid/gid. -1 means leave that id. Logs when ids change.
func Chown(path string, uid, gid int) error {
	st, err := os.Lstat(path)
	if err != nil {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		log.Printf("chown %s -> %d:%d", path, uid, gid)
		return nil
	}
	ou, og, ok := FileIDs(st)
	nu, ng := ou, og
	if uid >= 0 {
		nu = uid
	}
	if gid >= 0 {
		ng = gid
	}
	if ok && nu == ou && ng == og {
		return nil
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	log.Printf("chown %s %d:%d -> %d:%d", path, ou, og, nu, ng)
	return nil
}

// NoteChown logs a uid/gid change. No-op if ids are equal.
func NoteChown(path string, fromUID, fromGID, toUID, toGID int) {
	if fromUID == toUID && fromGID == toGID {
		return
	}
	log.Printf("chown %s %d:%d -> %d:%d", path, fromUID, fromGID, toUID, toGID)
}

func FileIDs(st os.FileInfo) (uid, gid int, ok bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(sys.Uid), int(sys.Gid), true
}
