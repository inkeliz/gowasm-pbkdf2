//go:build js && !native

package pbkdf2

import (
	"crypto"
	"syscall/js"

	"github.com/inkeliz/go_inkwasm/inkwasm"
	"golang.org/x/crypto/pbkdf2"
)

// key uses WebCrypto API to derive a key from a password and a salt.
func key(password, salt []byte, iter, keyLen int, h crypto.Hash) []byte {
	options := deriveKeyOptions{name: "PBKDF2", iterations: int32(iter), hash: ""}
	switch h {
	case crypto.SHA1:
		options.hash = "SHA-1"
	case crypto.SHA256:
		options.hash = "SHA-256"
	case crypto.SHA384:
		options.hash = "SHA-384"
	case crypto.SHA512:
		options.hash = "SHA-512"
	default:
		return keyNative(password, salt, iter, keyLen, h)
	}

	mode := deriveKeyMode{name: "AES-CBC"}
	switch keyLen {
	case 16:
		mode.length = 128
	case 24:
		mode.length = 192
	case 32:
		mode.length = 256
	default:
		return keyNative(password, salt, iter, keyLen, h)
	}

	webCrypto := getWebCryptoAPI()
	if !webCrypto.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}

	options.salt = copyArray(salt)
	defer options.salt.Free()

	passwordCopy := copyArray(password)
	defer passwordCopy.Free()

	importedKeyPromise, ok := importKey(webCrypto, "raw", passwordCopy, importKeyOptions{name: "PBKDF2"}, false, importKeyUsage)
	if !ok || !importedKeyPromise.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}
	defer importedKeyPromise.Free()

	importedKey, ok := waitPromise(importedKeyPromise)
	if !ok || !importedKey.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}
	defer importedKey.Free()

	derivedKeyPromise, ok := deriveKey(webCrypto, options, importedKey, mode, true, deriveKeyUsage)
	if !ok || !derivedKeyPromise.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}
	defer derivedKeyPromise.Free()

	derivedKey, ok := waitPromise(derivedKeyPromise)
	if !ok || !derivedKey.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}
	defer derivedKey.Free()

	resultKeyPromise, ok := exportKey(webCrypto, "raw", derivedKey)
	if !ok || !resultKeyPromise.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}
	defer resultKeyPromise.Free()

	resultKey, ok := waitPromise(resultKeyPromise)
	if !ok || !resultKey.Truthy() {
		return keyNative(password, salt, iter, keyLen, h)
	}
	defer resultKey.Free()

	result, err := resultKey.Bytes(nil)
	if err != nil {
		return keyNative(password, salt, iter, keyLen, h)
	}

	return result
}

func waitPromise(promise inkwasm.Object) (inkwasm.Object, bool) {
	pRes, pErr := make(chan inkwasm.Object, 1), make(chan struct{}, 1)
	defer func() {
		close(pRes)
		close(pErr)
	}()

	fRes := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pRes <- inkwasm.NewObjectFromSyscall(args[0])
		return nil
	})
	defer fRes.Release()

	fErr := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pErr <- struct{}{}
		return nil
	})
	defer fErr.Release()

	inkRes := inkwasm.NewObjectFromSyscall(fRes.Value)
	defer inkRes.Free()
	inkErr := inkwasm.NewObjectFromSyscall(fErr.Value)
	defer inkErr.Free()

	go func() {
		if _, err := promise.Call("then", inkRes, inkErr); err != nil {
			pErr <- struct{}{}
		}
	}()

	select {
	case res := <-pRes:
		return res, true
	case <-pErr:
		return inkwasm.Undefined(), false
	}
}

// keyNative is used as a fallback when WebCrypto API is not available, or
// the hash algorithm or size is not supported by WebCrypto API.
func keyNative(password, salt []byte, iter, keyLen int, h crypto.Hash) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, h.New)
}

//inkwasm:export
type importKeyOptions struct {
	_    uint64
	name string `js:"name"`
}

//inkwasm:export
type deriveKeyOptions struct {
	_          uint64
	name       string         `js:"name"`
	salt       inkwasm.Object `js:"salt"`
	iterations int32          `js:"iterations"`
	hash       string         `js:"hash"`
}

//inkwasm:export
type deriveKeyMode struct {
	_      uint64
	name   string `js:"name"`
	length int32  `js:"length"`
}

var importKeyUsage = newUsage("deriveBits", "deriveKey")

var deriveKeyUsage = newUsage("encrypt", "decrypt")

//inkwasm:new globalThis.Array
func newUsage(string, string) inkwasm.Object

//inkwasm:new globalThis.Uint8Array
func copyArray([]byte) inkwasm.Object

//inkwasm:get globalThis.crypto.subtle
func getWebCryptoAPI() inkwasm.Object

//inkwasm:func .importKey
func importKey(this inkwasm.Object, format string, key inkwasm.Object, params importKeyOptions, extractable bool, usages inkwasm.Object) (inkwasm.Object, bool)

//inkwasm:func .deriveKey
func deriveKey(this inkwasm.Object, params deriveKeyOptions, key inkwasm.Object, params2 deriveKeyMode, extractable bool, usages inkwasm.Object) (inkwasm.Object, bool)

//inkwasm:func .exportKey
func exportKey(this inkwasm.Object, format string, key inkwasm.Object) (inkwasm.Object, bool)
