// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
)

var mkdirUID = os.Getuid

func runMkdir(args []string) int {
	fs := flag.NewFlagSet("mkdir", flag.ExitOnError)
	defaults := fs.String("defaults", config.DefaultDistPath, "dist defaults (read DATA)")
	cfgFile := fs.String("config", config.DefaultConfigPath, "operator config (read DATA)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: bootstash mkdir [options] USER")
		return 2
	}
	cfg, err := config.LoadOperator(*defaults, *cfgFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := mkdirUser(mkdirUID(), cfg, fs.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "bootstash mkdir: %v\n", err)
		return 1
	}
	return 0
}

func mkdirUser(uid int, cfg *config.Config, user string) error {
	if uid != 0 {
		return errors.New("run as root")
	}
	if cfg == nil || !cfg.PAM {
		return errors.New("PAM=no has no users/ directory (bootstash put -email)")
	}
	if !pamauth.ValidUsername(user) {
		return fmt.Errorf("invalid user %q", user)
	}
	acct, err := pamauth.Lookup(user)
	if err != nil {
		return fmt.Errorf("unknown user %q", user)
	}
	if !pamauth.Linkable(acct) {
		return fmt.Errorf("%s cannot own a directory", user)
	}
	gid, err := pamauth.LookupGroupGID(cfg.UnixGroup)
	if err != nil {
		return fmt.Errorf("group %s: %w", cfg.UnixGroup, err)
	}
	users := filepath.Join(filepath.Clean(cfg.Data), "users")
	dir := filepath.Join(users, acct.Name)
	st, err := os.Lstat(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("%s: must be a directory, not a symlink", dir)
		}
		owner, _, ok := osutil.FileIDs(st)
		if !ok || owner != acct.UID {
			return fmt.Errorf("%s: not owned by %s", dir, acct.Name)
		}
	}
	return osutil.MkdirOwner(users, acct.Name, acct.UID, gid)
}
