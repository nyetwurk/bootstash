// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package jail confines filesystem operations to a directory file descriptor.
package jail

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nyet/bootstash/internal/osutil"
	"golang.org/x/sys/unix"
)

var (
	// ErrInvalid is a malformed (not merely missing) path.
	ErrInvalid = errors.New("invalid path")
	// ErrEscape is a path or symlink that would leave the jail.
	ErrEscape = errors.New("path escapes jail")
	// ErrNotEmpty is a directory that still has children.
	ErrNotEmpty = errors.New("directory not empty")
	// ErrNotDir is a path that exists but is not a directory.
	ErrNotDir = errors.New("not a directory")
)

const maxSymlinks = 8

// Root is an opened jail directory.
type Root struct {
	fd   int
	name string
}

// OpenRoot opens path as a jail root. It must be a directory.
func OpenRoot(path string) (*Root, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &Root{fd: fd, name: path}, nil
}

// Close closes the jail root directory.
func (r *Root) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

// Open opens a file or directory relative to the jail. Directories are
// readable; the returned file is owned by the caller.
func (r *Root) Open(rel string) (*os.File, error) {
	fd, err := r.resolve(rel, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), fileName(rel)), nil
}

// Create truncates or creates a file relative to the jail.
func (r *Root) Create(rel string, perm os.FileMode) (*os.File, error) {
	fd, err := r.resolve(rel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, uint32(perm&0777))
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), fileName(rel))
	if err := chmodNote(f, r.path(rel), perm); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Replace writes body to rel atomically: a sibling temp file, then
// renameat over the destination. A failed copy leaves the old file.
func (r *Root) Replace(rel string, perm os.FileMode, body io.Reader) error {
	dirfd, name, err := r.parentOf(rel)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".bootstash-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm&0777))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	if _, err := io.Copy(f, body); err != nil {
		f.Close()
		return err
	}
	if err := chmodNote(f, r.path(rel), perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// Mkdir creates a directory relative to the jail. It does not fchmod.
// Linux chmod by a process that is not in the directory's group and
// lacks CAP_FSETID silently drops S_ISGID (cubby is alice:bootstash;
// alice is not in bootstash). mkdirat in a setgid parent already
// inherits group and setgid; leave that in place.
func (r *Root) Mkdir(rel string, perm os.FileMode) error {
	dir, name, err := r.parentOf(rel)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return unix.Mkdirat(dir, name, uint32(perm&0777))
}

// Remove unlinks a file or empty directory inside the jail. It does not
// follow the last path component (a dangling or outbound symlink is
// unlinked, not traversed). The jail root cannot be removed.
func (r *Root) Remove(rel string) error {
	dir, name, err := r.parentOf(rel)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	flags := 0
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
	}
	if err := unix.Unlinkat(dir, name, flags); err != nil {
		if err == syscall.ENOTEMPTY || err == syscall.EEXIST {
			return ErrNotEmpty
		}
		return err
	}
	return nil
}

// Stat returns file info for a path inside the jail.
func (r *Root) Stat(rel string) (os.FileInfo, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

// Chown changes ownership of an existing path inside the jail.
func (r *Root) Chown(rel string, uid, gid int) error {
	f, err := r.Open(rel)
	if err != nil {
		return err
	}
	defer f.Close()
	fu, fg := -1, -1
	if st, err := f.Stat(); err == nil {
		if u, g, ok := osutil.FileIDs(st); ok {
			fu, fg = u, g
		}
	}
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	tu, tg := uid, gid
	if uid < 0 {
		tu = fu
	}
	if gid < 0 {
		tg = fg
	}
	osutil.NoteChown(r.path(rel), fu, fg, tu, tg)
	return nil
}

func fileName(rel string) string {
	if filepath.IsLocal(rel) {
		return rel
	}
	return "."
}

func chmodNote(f *os.File, path string, perm os.FileMode) error {
	from := os.FileMode(0)
	if st, err := f.Stat(); err == nil {
		from = st.Mode()
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	osutil.NoteChmod(path, from, perm)
	return nil
}

func (r *Root) path(rel string) string {
	if r.name == "" {
		return rel
	}
	return filepath.Join(r.name, filepath.FromSlash(rel))
}

func (r *Root) resolve(rel string, flags int, mode uint32) (int, error) {
	parts, err := components(rel)
	if err != nil {
		return -1, err
	}
	for n := 0; n < maxSymlinks; n++ {
		fd, newParts, err := r.walk(parts, flags, mode)
		if err != nil {
			return -1, err
		}
		if fd >= 0 {
			return fd, nil
		}
		parts = newParts
	}
	return -1, fmt.Errorf("%w: too many symlinks", ErrEscape)
}

func (r *Root) walk(parts []string, flags int, mode uint32) (int, []string, error) {
	dirfd, err := unix.FcntlInt(uintptr(r.fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	if len(parts) == 0 {
		if flags&unix.O_CREAT != 0 {
			unix.Close(dirfd)
			return -1, nil, ErrInvalid
		}
		return dirfd, nil, nil
	}
	for i, name := range parts {
		last := i == len(parts)-1
		openFlags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		openMode := uint32(0)
		if last {
			openFlags = flags | unix.O_NOFOLLOW | unix.O_CLOEXEC
			openMode = mode
		} else {
			openFlags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(dirfd, name, openFlags, openMode)
		if err != nil {
			if err == syscall.ELOOP || err == syscall.EMLINK || isSymlinkAt(dirfd, name) {
				buf := make([]byte, unix.PathMax)
				n, lerr := unix.Readlinkat(dirfd, name, buf)
				unix.Close(dirfd)
				if lerr != nil {
					return -1, nil, mapOpenErr(err)
				}
				target := string(buf[:n])
				if strings.HasPrefix(target, "/") {
					return -1, nil, ErrEscape
				}
				base := parts[:i]
				joined, jerr := joinComponents(base, target)
				if jerr != nil {
					return -1, nil, jerr
				}
				joined = append(joined, parts[i+1:]...)
				return -1, joined, nil
			}
			unix.Close(dirfd)
			return -1, nil, mapOpenErr(err)
		}
		unix.Close(dirfd)
		dirfd = fd
	}
	return dirfd, nil, nil
}

func (r *Root) parentOf(rel string) (int, string, error) {
	parts, err := components(rel)
	if err != nil {
		return -1, "", err
	}
	if len(parts) == 0 {
		return -1, "", ErrInvalid
	}
	parentParts := parts[:len(parts)-1]
	name := parts[len(parts)-1]
	fd, err := r.resolve(strings.Join(parentParts, "/"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	return fd, name, nil
}

func isSymlinkAt(dirfd int, name string) bool {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFLNK
}

func mapOpenErr(err error) error {
	if err == syscall.ENOENT {
		return err
	}
	if err == syscall.EACCES || err == syscall.EPERM {
		return err
	}
	return err
}

func components(rel string) ([]string, error) {
	if strings.IndexByte(rel, 0) >= 0 {
		return nil, ErrInvalid
	}
	if strings.ContainsRune(rel, '\\') {
		return nil, ErrInvalid
	}
	var out []string
	for _, p := range strings.Split(rel, "/") {
		switch p {
		case "", ".":
			continue
		case "..":
			if len(out) == 0 {
				return nil, ErrEscape
			}
			out = out[:len(out)-1]
		default:
			if strings.IndexByte(p, 0) >= 0 {
				return nil, ErrInvalid
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func joinComponents(base []string, target string) ([]string, error) {
	prefix := strings.Join(base, "/")
	if prefix == "" {
		return components(target)
	}
	return components(prefix + "/" + target)
}

// IsNotExist reports whether err is a missing path.
func IsNotExist(err error) bool {
	return errors.Is(err, syscall.ENOENT) || os.IsNotExist(err)
}

// ReadDirNames lists a directory inside the jail.
func (r *Root) ReadDirNames(rel string) ([]os.FileInfo, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, ErrNotDir
	}
	infos, err := f.Readdir(-1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return infos, nil
}
