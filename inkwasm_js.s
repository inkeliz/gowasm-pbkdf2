// Code generated by INKWASM BUILD; DO NOT EDIT
#include "textflag.h"

TEXT ·__newUsage(SB), NOSPLIT, $0
	CallImport
	RET

TEXT ·newUsage(SB), NOSPLIT, $0
	JMP ·_newUsage(SB)
	RET

TEXT ·__copyArray(SB), NOSPLIT, $0
	CallImport
	RET

TEXT ·copyArray(SB), NOSPLIT, $0
	JMP ·_copyArray(SB)
	RET

TEXT ·__getWebCryptoAPI(SB), NOSPLIT, $0
	CallImport
	RET

TEXT ·getWebCryptoAPI(SB), NOSPLIT, $0
	JMP ·_getWebCryptoAPI(SB)
	RET

TEXT ·__importKey(SB), NOSPLIT, $0
	CallImport
	RET

TEXT ·importKey(SB), NOSPLIT, $0
	JMP ·_importKey(SB)
	RET

TEXT ·__deriveKey(SB), NOSPLIT, $0
	CallImport
	RET

TEXT ·deriveKey(SB), NOSPLIT, $0
	JMP ·_deriveKey(SB)
	RET

TEXT ·__exportKey(SB), NOSPLIT, $0
	CallImport
	RET

TEXT ·exportKey(SB), NOSPLIT, $0
	JMP ·_exportKey(SB)
	RET
