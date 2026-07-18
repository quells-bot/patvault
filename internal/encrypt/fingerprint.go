package encrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// fingerprintLabel domain-separates the fingerprint HMAC from the AES key
// derivation (keyInfo). Bumping the version invalidates stored fingerprints.
const fingerprintLabel = "patvault-fingerprint-v1"

// Fingerprint returns a short, non-reversible identifier for token under
// masterKey: the first 8 lowercase base32 chars (40 bits) of
// HMAC-SHA256(masterKey, label || token). Stable per (masterKey, token) so it
// surfaces token reuse across repos; not comparable across master keys.
func Fingerprint(masterKey []byte, token string) string {
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte(fingerprintLabel))
	h.Write([]byte(token))
	sum := h.Sum(nil)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum)
	return strings.ToLower(enc)[:8]
}
