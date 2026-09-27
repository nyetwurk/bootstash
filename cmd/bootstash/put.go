// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/jail"
	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
)

const (
	putFileMode = 0660
	// mkdirat 0770; setgid comes from the cubby parent. Do not fchmod
	// (chmod(2) drops S_ISGID when the caller is not in group bootstash).
	putDirMode = 0770
)

type putUser struct {
	Name string
	UID  int
}

func runPut(args []string) int {
	u, err := lookupPutUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return putWith(u, os.Stdout, args)
}

var getuid = os.Getuid

func lookupPutUser() (putUser, error) {
	uid := getuid()
	if uid == 0 {
		return putUser{}, errors.New("bootstash put: run as the cubby owner, not root")
	}
	u, err := user.Current()
	if err != nil {
		return putUser{}, fmt.Errorf("bootstash put: %w", err)
	}
	if !pamauth.ValidUsername(u.Username) {
		return putUser{}, fmt.Errorf("bootstash put: invalid user %q", u.Username)
	}
	return putUser{Name: u.Username, UID: uid}, nil
}

func putWith(u putUser, w io.Writer, args []string) int {
	flags := flag.NewFlagSet("put", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	defaults := flags.String("defaults", config.DefaultDistPath, "dist defaults (read DATA)")
	cfgFile := flags.String("config", config.DefaultConfigPath, "operator config (read DATA)")
	destFlag := flags.String("t", "", "destination directory in the cubby")
	emailFlag := flags.String("email", "", "verified address cubby (PAM=no)")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bootstash put [options] [-t DIR] SRC [SRC...]")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	sources, dest, err := splitPutArgs(flags.Args(), *destFlag)
	if err != nil {
		flags.Usage()
		return 2
	}

	cfg, err := config.LoadOperator(*defaults, *cfgFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cubby, err := cubbyDir(cfg, u, *emailFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
		return 1
	}
	destRel, err := cubbyRel(cubby, dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
		return 1
	}

	root, err := jail.OpenRoot(cubby)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
		return 1
	}
	defer root.Close()

	// umask would turn mkdirat 0770 into 0750 (then 2750 with inherited
	// setgid). chmod cannot restore g+w without dropping S_ISGID.
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)

	if destRel != "" {
		if err := mkdirAll(root, destRel); err != nil {
			fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
			return 1
		}
	}

	for _, src := range sources {
		target, err := putTarget(src, destRel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
			return 1
		}
		if err := refuseSelfCopy(src, cubby, target); err != nil {
			fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
			return 1
		}
		if err := copyInto(root, src, target, w); err != nil {
			fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
			return 1
		}
	}
	return 0
}

// splitPutArgs treats every positional as a source. destFlag is the
// only destination, a directory inside the cubby (-t). Empty means
// the cubby root.
func splitPutArgs(args []string, destFlag string) (sources []string, dest string, err error) {
	if len(args) < 1 {
		return nil, "", errPutUsage
	}
	return args, destFlag, nil
}

var errPutUsage = errors.New("usage")

func cubbyDir(cfg *config.Config, u putUser, emailFlag string) (string, error) {
	if cfg == nil {
		return "", errors.New("no config")
	}
	if cfg.PAM {
		if emailFlag != "" {
			return "", errors.New("-email requires PAM=no")
		}
		return pamCubby(cfg.Data, u)
	}
	email, err := pickPutEmail(cfg, emailFlag)
	if err != nil {
		return "", err
	}
	id, err := config.EmailCubbyID(email)
	if err != nil {
		return "", err
	}
	return emailCubby(cfg.Data, u, id)
}

func pickPutEmail(cfg *config.Config, emailFlag string) (string, error) {
	if emailFlag != "" {
		n, err := config.NormalizeEmail(emailFlag)
		if err != nil {
			return "", fmt.Errorf("email: %w", err)
		}
		if len(cfg.AllowedEmails) == 0 || !cfg.AllowsEmail(n) {
			return "", fmt.Errorf("email %s is not in ALLOWED_EMAILS", n)
		}
		return n, nil
	}
	switch len(cfg.AllowedEmails) {
	case 1:
		return cfg.AllowedEmails[0], nil
	case 0:
		return "", errors.New("set ALLOWED_EMAILS or pass -email")
	default:
		return "", fmt.Errorf("pass -email (ALLOWED_EMAILS has %d addresses)", len(cfg.AllowedEmails))
	}
}

func emailCubby(data string, u putUser, id string) (string, error) {
	home := filepath.Join(data, "home")
	st, err := os.Lstat(home)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no %s (start bootstash once so it can create home/)", home)
		}
		if os.IsPermission(err) {
			return "", cannotCreateCubby(home)
		}
		return "", err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", fmt.Errorf("%s: not a directory", home)
	}
	cubby := filepath.Join(home, id)
	cst, err := os.Lstat(cubby)
	if err != nil {
		if os.IsPermission(err) {
			return "", cannotCreateCubby(home)
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		// umask 0 so the directory is 0770. Linux copies S_ISGID from
		// the parent. Darwin does not; chmod it on only when missing.
		// chmod of a directory that already has the bit can clear it
		// when the caller is not in that group.
		old := syscall.Umask(0)
		mkErr := os.Mkdir(cubby, 0770)
		syscall.Umask(old)
		if mkErr != nil {
			if os.IsPermission(mkErr) {
				return "", cannotCreateCubby(home)
			}
			return "", mkErr
		}
		if err := copySetgid(home, cubby); err != nil {
			return "", err
		}
		cst, err = os.Lstat(cubby)
		if err != nil {
			return "", err
		}
		if cst.Mode()&os.ModeSetgid == 0 || cst.Mode().Perm()&0o070 != 0o070 {
			return "", fmt.Errorf("%s: cubby is missing setgid or group access (%s must be mode 03773)", cubby, home)
		}
		return cubby, nil
	}
	if _, err := ownedCubby(cubby, cst, u); err != nil {
		return "", err
	}
	return cubby, nil
}

func cannotCreateCubby(home string) error {
	return fmt.Errorf("cannot create a directory in %s (want mode 03773)", home)
}

// copySetgid sets S_ISGID on cubby when parent has it and cubby does not.
// Linux mkdir already copies the bit. Darwin does not.
func copySetgid(parent, cubby string) error {
	pst, err := os.Lstat(parent)
	if err != nil || pst.Mode()&os.ModeSetgid == 0 {
		return err
	}
	st, err := os.Lstat(cubby)
	if err != nil || st.Mode()&os.ModeSetgid != 0 {
		return err
	}
	return os.Chmod(cubby, os.ModeSetgid|st.Mode().Perm())
}

func pamCubby(data string, u putUser) (string, error) {
	if !pamauth.ValidUsername(u.Name) || !filepath.IsLocal(u.Name) {
		return "", fmt.Errorf("invalid user %q", u.Name)
	}
	cubby := filepath.Join(data, "users", u.Name)
	st, err := os.Lstat(cubby)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no cubby for %s (sign in and link first)", u.Name)
		}
		return "", err
	}
	return ownedCubby(cubby, st, u)
}

func ownedCubby(cubby string, st os.FileInfo, u putUser) (string, error) {
	if st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s: cubby must be a directory, not a symlink", cubby)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s: not a directory", cubby)
	}
	uid, _, ok := osutil.FileIDs(st)
	if !ok || uid != u.UID {
		return "", fmt.Errorf("%s: not owned by %s", cubby, u.Name)
	}
	return cubby, nil
}

func cubbyRel(cubby, dest string) (string, error) {
	if dest == "" || dest == "." || dest == "/" {
		return "", nil
	}
	cubby = filepath.Clean(cubby)
	if filepath.IsAbs(dest) {
		cleaned, err := osutil.Confine(cubby, dest)
		if err != nil {
			return "", fmt.Errorf("destination %s is outside the cubby", dest)
		}
		rel, err := filepath.Rel(cubby, cleaned)
		if err != nil {
			return "", err
		}
		if rel == "." {
			return "", nil
		}
		return filepath.ToSlash(rel), nil
	}
	rel := filepath.ToSlash(filepath.Clean(dest))
	rel = strings.TrimPrefix(rel, "/")
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", jail.ErrEscape
	}
	if rel == "." {
		return "", nil
	}
	return rel, nil
}

func putTarget(src, destRel string) (string, error) {
	base := filepath.Base(strings.TrimRight(src, string(filepath.Separator)))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", fmt.Errorf("%s: invalid source name", src)
	}
	if destRel == "" {
		return base, nil
	}
	return destRel + "/" + base, nil
}

func refuseSelfCopy(src, cubby, destRel string) error {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	srcAbs = filepath.Clean(srcAbs)
	destAbs := cubby
	if destRel != "" {
		destAbs = filepath.Join(cubby, filepath.FromSlash(destRel))
	}
	destAbs = filepath.Clean(destAbs)
	if srcAbs == destAbs {
		return fmt.Errorf("cannot put %s onto itself", src)
	}
	sep := string(filepath.Separator)
	if strings.HasPrefix(destAbs, srcAbs+sep) {
		return fmt.Errorf("cannot put %s into a subdirectory of itself", src)
	}
	return nil
}

func copyInto(root *jail.Root, src, destRel string, w io.Writer) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s: symlink not copied", src)
	case st.IsDir():
		return copyDir(root, src, destRel, w)
	case st.Mode().IsRegular():
		if err := copyFile(root, src, destRel); err != nil {
			return err
		}
		if w != nil {
			fmt.Fprintln(w, destRel)
		}
		return nil
	default:
		return fmt.Errorf("%s: not a regular file or directory", src)
	}
}

func copyFile(root *jail.Root, src, destRel string) error {
	if err := ensureParents(root, destRel); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return root.Replace(destRel, putFileMode, f)
}

func copyDir(root *jail.Root, src, destRel string, w io.Writer) error {
	if destRel != "" {
		if err := mkdirAll(root, destRel); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		from := filepath.Join(src, e.Name())
		to := e.Name()
		if destRel != "" {
			to = destRel + "/" + e.Name()
		}
		if err := copyInto(root, from, to, w); err != nil {
			return err
		}
	}
	return nil
}

func ensureParents(root *jail.Root, destRel string) error {
	dir := path.Dir(destRel)
	if dir == "." || dir == "/" || dir == "" {
		return nil
	}
	return mkdirAll(root, dir)
}

func mkdirAll(root *jail.Root, rel string) error {
	acc := ""
	for _, p := range strings.Split(rel, "/") {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return jail.ErrEscape
		}
		if acc == "" {
			acc = p
		} else {
			acc += "/" + p
		}
		if err := mkdirExistOK(root, acc); err != nil {
			return err
		}
	}
	return nil
}

func mkdirExistOK(root *jail.Root, rel string) error {
	err := root.Mkdir(rel, putDirMode)
	if err == nil {
		return nil
	}
	if err != syscall.EEXIST && !errors.Is(err, fs.ErrExist) {
		return err
	}
	st, sterr := root.Stat(rel)
	if sterr != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s: not a directory", rel)
	}
	return nil
}
