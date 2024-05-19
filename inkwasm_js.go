// Code generated by INKWASM BUILD; DO NOT EDIT

package pbkdf2

import (
	"runtime"

	"github.com/inkeliz/go_inkwasm/inkwasm"
)

func _newUsage(p0 string, p1 string) (_ inkwasm.Object) {
	r0 := __newUsage(p0, p1)
	runtime.KeepAlive(p0)
	runtime.KeepAlive(p1)

	return r0
}

//go:wasmimport gojs github.com/inkeliz/gowasm-pbkdf2.__newUsage
func __newUsage(p0 string, p1 string) (_ inkwasm.Object)

func _copyArray(p0 []byte) (_ inkwasm.Object) {
	r0 := __copyArray(p0)
	runtime.KeepAlive(p0)

	return r0
}

//go:wasmimport gojs github.com/inkeliz/gowasm-pbkdf2.__copyArray
func __copyArray(p0 []byte) (_ inkwasm.Object)

func _getWebCryptoAPI() (_ inkwasm.Object) {
	r0 := __getWebCryptoAPI()

	return r0
}

//go:wasmimport gojs github.com/inkeliz/gowasm-pbkdf2.__getWebCryptoAPI
func __getWebCryptoAPI() (_ inkwasm.Object)

func _importKey(this inkwasm.Object, format string, key inkwasm.Object, params importKeyOptions, extractable bool, usages inkwasm.Object) (_ inkwasm.Object, _ bool) {
	r0, r1 := __importKey(this, format, key, params, extractable, usages)
	runtime.KeepAlive(format)

	return r0, r1
}

//go:wasmimport gojs github.com/inkeliz/gowasm-pbkdf2.__importKey
func __importKey(this inkwasm.Object, format string, key inkwasm.Object, params importKeyOptions, extractable bool, usages inkwasm.Object) (_ inkwasm.Object, _ bool)

func _deriveKey(this inkwasm.Object, params deriveKeyOptions, key inkwasm.Object, params2 deriveKeyMode, extractable bool, usages inkwasm.Object) (_ inkwasm.Object, _ bool) {
	r0, r1 := __deriveKey(this, params, key, params2, extractable, usages)

	return r0, r1
}

//go:wasmimport gojs github.com/inkeliz/gowasm-pbkdf2.__deriveKey
func __deriveKey(this inkwasm.Object, params deriveKeyOptions, key inkwasm.Object, params2 deriveKeyMode, extractable bool, usages inkwasm.Object) (_ inkwasm.Object, _ bool)

func _exportKey(this inkwasm.Object, format string, key inkwasm.Object) (_ inkwasm.Object, _ bool) {
	r0, r1 := __exportKey(this, format, key)
	runtime.KeepAlive(format)

	return r0, r1
}

//go:wasmimport gojs github.com/inkeliz/gowasm-pbkdf2.__exportKey
func __exportKey(this inkwasm.Object, format string, key inkwasm.Object) (_ inkwasm.Object, _ bool)
