// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package version holds the build identity from git describe.
package version

// Version is set at link time with
// -X github.com/nyet/bootstash/internal/version.Version=$(git describe ...).
// The default is used for go test / go run without linker flags.
var Version = "unknown"
