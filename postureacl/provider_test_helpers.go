// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package postureacl

import "tailscale.com/util/testenv"

// RegisterCheckProviderForTest registers p as the sole check provider for the
// duration of a test and returns a restore function that reinstates the
// previous providers. It is only available in test builds.
func RegisterCheckProviderForTest(p CheckProvider) (restore func()) {
	testenv.AssertInTest()
	providerMu.Lock()
	old := providers
	providers = []CheckProvider{p}
	providerMu.Unlock()
	return func() {
		providerMu.Lock()
		providers = old
		providerMu.Unlock()
	}
}
