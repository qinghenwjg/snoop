package utils

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
)

const (
	// CustomKey custom key
	CustomKey = "horus-kit maybe is the best kitt"
)

// AesEncryptByECB encrypt data
func AesEncryptByECB(data, key string) (string, error) {
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
		return "", fmt.Errorf("encrypt key length error")
	}

	originByte := []byte(data)
	keyByte := []byte(key)

	block, _ := aes.NewCipher(keyByte)
	blockSize := block.BlockSize()

	originByte = PKCS7Padding(originByte, blockSize)

	encryptResult := make([]byte, len(originByte))

	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encryptResult[bs:be], originByte[bs:be])
	}

	return base64.StdEncoding.EncodeToString(encryptResult), nil
}

// PKCS7Padding pack
func PKCS7Padding(originByte []byte, blockSize int) []byte {
	padding := blockSize - len(originByte)%blockSize

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(originByte, padText...)
}

// AesDecryptByECB decrypt data
func AesDecryptByECB(data, key string) string {
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
		return ""
	}

	originByte, _ := base64.StdEncoding.DecodeString(data)
	keyByte := []byte(key)
	block, _ := aes.NewCipher(keyByte)

	blockSize := block.BlockSize()

	decrypted := make([]byte, len(originByte))

	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted[bs:be], originByte[bs:be])
	}

	return string(PKCS7UNPadding(decrypted))
}

// PKCS7UNPadding unpack
func PKCS7UNPadding(originDataByte []byte) []byte {
	length := len(originDataByte)
	unpadding := int(originDataByte[length-1])
	return originDataByte[:(length - unpadding)]
}
