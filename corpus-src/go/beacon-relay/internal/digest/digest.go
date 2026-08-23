// Package digest computes the content addresses used by the relay's dedup cache.
//
// The import is aliased to "checksum" because an earlier revision of the relay
// swapped hash functions twice, and the call sites should not have to change
// again if it ever swaps a third time.
package digest

import (
	"encoding/hex"

	checksum "crypto/sha256" //@PS +go-l2-sha256
)

// Size is the length of a content address in bytes.
const Size = checksum.Size

// Of returns the content address of a beacon body.
func Of(body []byte) string {
	sum := checksum.Sum256(body) //@PS go-l2-sha256|SHA-256|2|algorithm|aliased import: crypto/sha256 imported as "checksum"
	return hex.EncodeToString(sum[:])
}

// Matches reports whether body still hashes to the recorded address.
func Matches(body []byte, address string) bool {
	return Of(body) == address
}
