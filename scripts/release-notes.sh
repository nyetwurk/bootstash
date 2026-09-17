#!/bin/sh
# Copyright (C) 2026 Nye Liu
# SPDX-License-Identifier: GPL-3.0-or-later
#
# github → stdout markdown (git-cliff body)
# debian → stdout debian/changelog
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

usage() {
	echo "usage: release-notes.sh github|debian" >&2
	exit 2
}

[ "${1:-}" = github ] || [ "${1:-}" = debian ] || usage
mode=$1
ver=$(sh "$root/scripts/deb-version.sh")
rc_ignore='v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+'
in_git=0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 && in_git=1

tag=
if [ "$in_git" -eq 1 ]; then
	tag=$(git describe --tags --exact-match 2>/dev/null || true)
fi

is_release() {
	printf '%s' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

is_rc() {
	printf '%s' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$'
}

github_notes() {
	if ! command -v git-cliff >/dev/null 2>&1; then
		echo "release-notes.sh: git-cliff is required" >&2
		exit 1
	fi
	if [ "$in_git" -ne 1 ]; then
		echo "release-notes.sh: not a git repository" >&2
		exit 1
	fi
	if is_release "$tag"; then
		git-cliff --latest --strip header --ignore-tags "$rc_ignore"
	elif is_rc "$tag"; then
		git-cliff --latest --strip header
	else
		git-cliff --unreleased --strip header
	fi
}

debian_notes() {
	if command -v git-cliff >/dev/null 2>&1 && [ "$in_git" -eq 1 ]; then
		if git-cliff --context --offline | python3 "$root/scripts/debian-changelog.py" "$ver"; then
			return 0
		fi
	fi
	python3 "$root/scripts/debian-changelog.py" "$ver" </dev/null
}

case "$mode" in
github) github_notes ;;
debian) debian_notes ;;
esac
