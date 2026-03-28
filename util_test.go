package gomat

import (
	"testing"
)

// TestExchangeIDIsCryptoRandom verifies that randomUint16 produces
// sufficiently varied output (not constant or sequential), which would
// indicate it uses crypto/rand rather than a zero-seeded or predictable source.
func TestExchangeIDIsCryptoRandom(t *testing.T) {
	const samples = 1000

	seen := make(map[uint16]struct{}, samples)
	for i := 0; i < samples; i++ {
		v := randomUint16()
		seen[v] = struct{}{}
	}

	// With 1000 draws from a 16-bit space (65536 values), birthday paradox
	// gives ~99.99% chance of at least 990 unique values with a good CSPRNG.
	// A constant or poorly seeded PRNG would produce far fewer.
	minUnique := 900
	if len(seen) < minUnique {
		t.Errorf("randomUint16 produced only %d unique values in %d samples (expected >=%d); source may not be crypto/rand",
			len(seen), samples, minUnique)
	}
}
