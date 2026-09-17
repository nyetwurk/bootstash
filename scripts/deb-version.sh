#!/bin/sh
# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Exact legal tag → Debian version. Else 0.0.0~git+describe.
set -eu

sanitize() {
	printf '%s' "$1" | tr -c 'A-Za-z0-9.+~' '.'
}

untagged() {
	desc=unknown
	if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		desc=$(git describe --tags --abbrev=4 --always 2>/dev/null || echo unknown)
	fi
	printf '0.0.0~git+%s\n' "$(sanitize "$desc")"
}

# Version written into debian/changelog for the last make deb, if any.
packaged() {
	if [ -f debian/changelog ]; then
		sed -n 's/^bootstash (\([^)]*\)).*/\1/p' debian/changelog | head -n1
		return
	fi
	untagged
}

if [ "${1:-}" = packaged ]; then
	packaged
	exit 0
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	untagged
	exit 0
fi

tag=$(git describe --tags --exact-match 2>/dev/null || true)
if [ -n "$tag" ] && printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$'; then
	ver=${tag#v}
	printf '%s\n' "$(printf '%s' "$ver" | sed 's/-rc/~rc/')"
	exit 0
fi

untagged
