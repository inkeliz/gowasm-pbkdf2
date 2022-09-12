package pbkdf2

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"testing"

	_ "golang.org/x/crypto/blake2b"
)

func TestKey(t *testing.T) {
	if !bytes.Equal(key([]byte("password"), []byte("salt"), 10_000, 32, crypto.SHA512), keyNative([]byte("password"), []byte("salt"), 10_000, 32, crypto.SHA512)) {
		t.Fail()
	}
}

func TestKeyDifferent(t *testing.T) {
	if bytes.Equal(key([]byte("password2"), []byte("salt"), 10_000, 32, crypto.SHA512), keyNative([]byte("password"), []byte("salt"), 10_000, 32, crypto.SHA512)) {
		t.Fail()
	}
}

func TestKeyDifferentSalt(t *testing.T) {
	if bytes.Equal(key([]byte("password"), []byte("salt2"), 10_000, 32, crypto.SHA512), keyNative([]byte("password"), []byte("salt"), 10_000, 32, crypto.SHA512)) {
		t.Fail()
	}
}

func TestKeyDifferentIterations(t *testing.T) {
	if bytes.Equal(key([]byte("password"), []byte("salt"), 10_001, 32, crypto.SHA512), keyNative([]byte("password"), []byte("salt"), 10_000, 32, crypto.SHA512)) {
		t.Fail()
	}
}

func TestKeyUnsupported(t *testing.T) {
	if !bytes.Equal(key([]byte("password"), []byte("salt"), 10_000, 32, crypto.BLAKE2b_384), keyNative([]byte("password"), []byte("salt"), 10_000, 32, crypto.BLAKE2b_384)) {
		t.Fail()
	}
}

func TestKeyUnsupportedKeyLen(t *testing.T) {
	for i := 0; i < 100; i++ {
		if !bytes.Equal(key([]byte("password"), []byte("salt"), 10, i, crypto.SHA512), keyNative([]byte("password"), []byte("salt"), 10, i, crypto.SHA512)) {
			t.Fail()
		}
	}
}

func TestKey3(t *testing.T) {
	algos := []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.MD5, crypto.BLAKE2b_256, crypto.BLAKE2b_384, crypto.BLAKE2b_512}
	sizes := []int{8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
	passwords := []string{"password", "12345678", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}

	for _, algo := range algos {
		for _, size := range sizes {
			for _, password := range passwords {
				for _, sizeSalt := range sizes {
					salt := make([]byte, sizeSalt)
					rand.Read(salt)

					if !bytes.Equal(key([]byte(password), salt, 100, size, algo), keyNative([]byte(password), salt, 100, size, algo)) {
						t.Fail()
					}
				}
			}
		}
	}

}

func BenchmarkKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key([]byte("password"), []byte("salt"), 100_000, 32, crypto.SHA512)
	}
}

func BenchmarkNativeKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		keyNative([]byte("password"), []byte("salt"), 100_000, 32, crypto.SHA512)
	}
}
