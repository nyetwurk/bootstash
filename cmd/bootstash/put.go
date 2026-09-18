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
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bootstash put [options] SRC [SRC...] [DEST]")
		fmt.Fprintln(os.Stderr, "       bootstash put [options] -t DEST SRC [SRC...]")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	sources, dest, destDir, err := splitPutArgs(flags.Args(), *destFlag)
	if err != nil {
		flags.Usage()
		return 2
	}

	cfg, err := config.LoadOperator(*defaults, *cfgFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cubby, err := cubbyDir(cfg.Data, u)
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

	if !destDir {
		if st, err := root.Stat(destRel); err == nil && st.IsDir() {
			destDir = true
		}
	}
	if destDir && destRel != "" {
		if err := mkdirAll(root, destRel); err != nil {
			fmt.Fprintf(os.Stderr, "bootstash put: %v\n", err)
			return 1
		}
	}

	for _, src := range sources {
		target, err := putTarget(src, destRel, destDir)
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

func splitPutArgs(args []string, destFlag string) (sources []string, dest string, destDir bool, err error) {
	if destFlag != "" {
		if len(args) < 1 {
			return nil, "", false, errPutUsage
		}
		return args, destFlag, true, nil
	}
	switch len(args) {
	case 0:
		return nil, "", false, errPutUsage
	case 1:
		return args, "", true, nil
	default:
		dest = args[len(args)-1]
		sources = args[:len(args)-1]
		destDir = len(sources) > 1 || strings.HasSuffix(dest, "/") || dest == "." || dest == "/"
		return sources, dest, destDir, nil
	}
}

var errPutUsage = errors.New("usage")

func cubbyDir(data string, u putUser) (string, error) {
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

func putTarget(src, destRel string, destDir bool) (string, error) {
	base := filepath.Base(strings.TrimRight(src, string(filepath.Separator)))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", fmt.Errorf("%s: invalid source name", src)
	}
	if !destDir {
		if destRel == "" {
			return base, nil
		}
		return destRel, nil
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
