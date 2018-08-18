package gotra

import "golang.org/x/crypto/sha3"

func kdfPrekeyServer(usageID uint8, size uint16, values ...[]byte) []byte {
	buf := make([]byte, size)
	kdfxPrekeyServer(usageID, buf, values...)
	return buf
}

func kdfxPrekeyServer(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append(kdfPrekeyServerPrefix, usageID), concat(values...)...))
}

func kdf(usageID uint8, size uint16, values ...[]byte) []byte {
	buf := make([]byte, size)
	kdfx(usageID, buf, values...)
	return buf
}

func kdfx(usageID uint8, buf []byte, values ...[]byte) {
	sha3.ShakeSum256(buf, append(append(kdfPrefix, usageID), concat(values...)...))
}

func concat(values ...[]byte) []byte {
	result := []byte{}
	for _, v := range values {
		result = append(result, v...)
	}
	return result
}
