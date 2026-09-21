# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later

.PHONY: all test fmt clean distclean changelog copyright deb packages lintian FORCE

BINDIR := bin
GIT_VERSION := $(shell git describe --tags --abbrev=4 --dirty --always 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/nyet/bootstash/internal/version.Version=$(GIT_VERSION)
# -d: Build-Depends name a Debian golang-go; PATH go (setup-go / local) is enough.
# dpkg default is .. ; make packages / CI use packages/. Bare dpkg-buildpackage still uses ...
# Only these two: empty or / would make mkdir/mv target the root.
export PKG_OUT ?= packages
ifeq ($(filter $(PKG_OUT),packages ..),)
$(error PKG_OUT must be 'packages' or '..')
endif

all: $(BINDIR)/bootstashd $(BINDIR)/bootstash $(BINDIR)/bootstash-pam

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/bootstashd: FORCE | $(BINDIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/bootstashd

$(BINDIR)/bootstash: FORCE | $(BINDIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/bootstash

$(BINDIR)/bootstash-pam: FORCE | $(BINDIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/bootstash-pam

test:
	go test ./...
	python3 scripts/test-letsencrypt-deploy.py

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './debian/*')

changelog:
	sh scripts/release-notes.sh debian > debian/changelog

# Refresh the generated Go-module list in debian/copyright (committed).
copyright:
	python3 scripts/debian-copyright-modules.py

# dpkg-buildpackage always writes to ... make deb gathers into $(PKG_OUT).
deb: changelog
	dpkg-buildpackage -b -us -uc -d
	@if [ "$(PKG_OUT)" = packages ]; then \
		mkdir -p packages; \
		mv -f ../bootstash_*.deb ../bootstash_*.buildinfo ../bootstash_*.changes packages/; \
	fi

# All shipped archives. Today: Debian. Later: dmg / brew.
packages: deb

# Version comes from debian/changelog (what make deb built), not a
# second git describe — dpkg-buildpackage can dirty the tree.
lintian:
	@ver=$$(sh scripts/deb-version.sh packaged); \
	set -- packages/bootstash_$${ver}_*.changes; \
	if [ "$(PKG_OUT)" = .. ]; then set -- ../bootstash_$${ver}_*.changes; fi; \
	if [ ! -e "$$1" ]; then \
		echo "lintian: no $$1 (run make deb)" >&2; \
		exit 1; \
	fi; \
	lintian --fail-on warning "$$@"

clean:
	rm -rf bin

# Only the known dirs. Never rm -rf $(PKG_OUT) — that can be .. or worse.
# debian/rules must call `make clean` only — dh_auto_clean would pick this
# and delete debian/changelog mid-build.
distclean: clean
	rm -f debian/changelog
	rm -rf packages

FORCE:
