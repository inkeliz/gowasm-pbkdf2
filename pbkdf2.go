package pbkdf2

import (
	"crypto"
)

// Key derives a key from the password, salt and iteration count, returning a
// []byte of length keylen that can be used as cryptographic key. The key is
// derived based on the method described as PBKDF2 with the HMAC variant using
// the supplied hash function.
//
// For example, to use a HMAC-SHA-1 based PBKDF2 key derivation function, you
// can get a derived key for e.g. AES-256 (which needs a 32-byte key) by
// doing:
//
//	dk := pbkdf2.Key([]byte("some password"), salt, 1_000_000, 32, crypto.SHA1)
//
// Remember to get a good random salt (at least 8 bytes is recommended by the
// RFC). Also, you MUST import `crypto/sha1` to use the SHA1 hash function, as
// it is not imported by default. The same applies to other hash functions, see
// the documentation of the crypto package for more information.
//
// Using a higher iteration count will increase the cost of an exhaustive
// search but will also make derivation proportionally slower. The iteration
// count should be increased as CPU power increases, so it is recommended to
// store the iteration together with the salt and derived key, so that the
// parameters can be adjusted for future use and re-hash with new iteration
// counts.
func Key(password, salt []byte, iter, keyLen int, h crypto.Hash) []byte {
	// This function depends on the current OS/ARCH. See pbkdf2_native.go and
	// pbkdf2_js.go for the actual implementation.
	return key(password, salt, iter, keyLen, h)
}
