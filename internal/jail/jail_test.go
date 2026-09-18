// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package jail

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRejectDotDot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("no"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Open("../" + filepath.Base(outside) + "/secret"); err == nil {
		t.Fatal("expected escape")
	}
	if _, err := j.Open(".."); err == nil {
		t.Fatal("expected escape")
	}
	if _, err := j.Open("foo/../../etc/passwd"); err == nil {
		t.Fatal("expected escape")
	}
}

func TestExtraSlashes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("//a///b.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
}

func TestFileNameIsLocal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Name() != "ok.txt" {
		t.Fatalf("name %q", f.Name())
	}
}

func TestSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("no"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(root, "up")); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Open("escape"); err == nil {
		t.Fatal("absolute symlink should fail")
	}
	if _, err := j.Open("up"); err == nil {
		t.Fatal(".. symlink should fail")
	}
}

func TestInternalSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "hello.txt"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("b/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2)
	n, err := f.Read(buf)
	if err != nil || n != 2 || string(buf) != "hi" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}

func TestNUL(t *testing.T) {
	root := t.TempDir()
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Open("foo\x00bar"); err == nil {
		t.Fatal("expected invalid")
	}
}

func TestCreateAndMkdir(t *testing.T) {
	root := t.TempDir()
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Mkdir("sub", 0770); err != nil {
		t.Fatal(err)
	}
	f, err := j.Create("sub/file.txt", 0660)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := j.Create("../nope", 0660); err == nil {
		t.Fatal("create escape")
	}
}

func TestRemoveFileAndEmptyDir(t *testing.T) {
	root := t.TempDir()
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Mkdir("sub", 0770); err != nil {
		t.Fatal(err)
	}
	f, err := j.Create("sub/file.txt", 0660)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := j.Remove("sub"); err != ErrNotEmpty {
		t.Fatalf("expected not empty, got %v", err)
	}
	if err := j.Remove("sub/file.txt"); err != nil {
		t.Fatal(err)
	}
	if err := j.Remove("sub"); err != nil {
		t.Fatal(err)
	}
	if err := j.Remove(""); err == nil {
		t.Fatal("removed jail root")
	}
	if err := j.Remove("../nope"); err == nil {
		t.Fatal("remove escape")
	}
}

func TestRemoveSymlinkDoesNotFollow(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Remove("escape"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatal("followed symlink and removed outside file")
	}
}

func TestReadDirNamesNotDir(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.ReadDirNames("f.txt"); err != ErrNotDir {
		t.Fatalf("got %v", err)
	}
}

func TestComponents(t *testing.T) {
	tests := []struct {
		in   string
		want []string
		err  error
	}{
		{"", nil, nil},
		{".", nil, nil},
		{"foo", []string{"foo"}, nil},
		{"foo/bar", []string{"foo", "bar"}, nil},
		{"//a///b", []string{"a", "b"}, nil},
		{"foo/./bar", []string{"foo", "bar"}, nil},
		{"foo/../bar", []string{"bar"}, nil},
		{"foo/..", nil, nil},
		{"...", []string{"..."}, nil},
		{"..", nil, ErrEscape},
		{"foo/../../bar", nil, ErrEscape},
		{"foo\x00bar", nil, ErrInvalid},
		{`foo\bar`, nil, ErrInvalid},
	}
	for _, tc := range tests {
		got, err := components(tc.in)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Fatalf("%q: err %v want %v", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%q: %v want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%q: %v want %v", tc.in, got, tc.want)
			}
		}
	}
}

func FuzzComponents(f *testing.F) {
	for _, s := range []string{"a/b", "..", "a/../b", "foo\x00bar", `a\b`, "//.", "a/../../x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		parts, err := components(rel)
		if err != nil {
			return
		}
		for _, p := range parts {
			if p == "" || p == "." || p == ".." || strings.ContainsRune(p, 0) || strings.Contains(p, "/") || strings.ContainsRune(p, '\\') {
				t.Fatalf("part %q from %q", p, rel)
			}
		}
	})
}

func TestHardlinkRemoveKeepsOtherName(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(root, "x")); err != nil {
		t.Skip(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Open("x")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := f.Read(buf)
	f.Close()
	if err != nil || n != 4 || string(buf) != "keep" {
		t.Fatalf("open hardlink %q %v", buf[:n], err)
	}
	if err := j.Remove("x"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(secret)
	if err != nil || string(got) != "keep" {
		t.Fatalf("outside %q %v", got, err)
	}
}

func TestHardlinkInsideJailSharesInode(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.txt")
	if err := os.WriteFile(a, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, filepath.Join(root, "b.txt")); err != nil {
		t.Skip(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	f, err := j.Create("a.txt", 0660)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := os.ReadFile(filepath.Join(root, "b.txt"))
	if err != nil || string(got) != "two" {
		t.Fatalf("shared inode %q %v", got, err)
	}
	if err := j.Remove("a.txt"); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(root, "b.txt"))
	if err != nil || string(got) != "two" {
		t.Fatalf("after unlink %q %v", got, err)
	}
}

func TestCreateDoesNotTruncateOutsideHardlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(root, "x")); err != nil {
		t.Skip(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Replace("x", 0660, strings.NewReader("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(secret)
	if err != nil || string(got) != "keep" {
		t.Fatalf("outside %q %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(root, "x"))
	if err != nil || string(got) != "new" {
		t.Fatalf("jail %q %v", got, err)
	}
}

func TestReplaceFailureKeepsOld(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- j.Replace("f.txt", 0660, r)
	}()
	if _, err := w.Write([]byte("xx")); err != nil {
		t.Fatal(err)
	}
	_ = w.CloseWithError(io.ErrUnexpectedEOF)
	if err := <-errc; err == nil {
		t.Fatal("expected replace error")
	}
	got, err := os.ReadFile(filepath.Join(root, "f.txt"))
	if err != nil || string(got) != "old" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestSwapDoesNotTouchOutside(t *testing.T) {
	if testing.Short() {
		t.Skip("symlink swap")
	}
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	want := []byte("keep-me-please")
	if err := os.WriteFile(secret, want, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	x := filepath.Join(root, "x")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.RemoveAll(x)
			_ = os.WriteFile(x, []byte("in"), 0600)
			_ = os.RemoveAll(x)
			_ = os.Symlink(secret, x)
			_ = os.RemoveAll(x)
			_ = os.Mkdir(x, 0700)
		}
	}()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if f, err := j.Open("x"); err == nil {
			buf := make([]byte, 32)
			n, _ := f.Read(buf)
			f.Close()
			if bytes.Contains(buf[:n], want) {
				close(stop)
				wg.Wait()
				t.Fatalf("read outside %q", buf[:n])
			}
		}
		if f, err := j.Create("x", 0600); err == nil {
			_, _ = f.Write([]byte("new"))
			f.Close()
		}
		_ = j.Remove("x")
	}
	close(stop)
	wg.Wait()
	got, err := os.ReadFile(secret)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("outside %q %v", got, err)
	}
}
