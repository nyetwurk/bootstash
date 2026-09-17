// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package version

import "testing"

func TestDefaultVersion(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must be non-empty")
	}
}
