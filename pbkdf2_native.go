//go:build !js && !native

package pbkdf2

import (
	"crypto"

	"golang.org/x/crypto/pbkdf2"
)

// key is a wrapper around pbkdf2.Key.
func key(password, salt []byte, iter, keyLen int, h crypto.Hash) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, h.New)
}
