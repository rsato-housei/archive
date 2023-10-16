package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
)

var HASHKEY, _ = hex.DecodeString("645E739A7F9F162725C1533DC2C5E827")

// func main() {
// 	pass := "password"
// 	encrypted, _ := bcrypt.GenerateFromPassword([]byte(pass), 4)
// 	hashedPass := hex.EncodeToString(encrypted)
// 	println(hashedPass)
// }

func generateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}
func pkcs7Pad(data []byte) []byte {
	length := aes.BlockSize - (len(data) % aes.BlockSize)
	trailing := bytes.Repeat([]byte{byte(length)}, length)
	return append(data, trailing...)
}

func Encrypt(text string) (iv []byte, encrypted []byte, err error) {
	iv, err = generateIV()
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(HASHKEY)
	if err != nil {
		return nil, nil, err
	}
	padded := pkcs7Pad([]byte(text))
	encrypted = make([]byte, len(padded))
	cbcEncrypter := cipher.NewCBCEncrypter(block, iv)
	cbcEncrypter.CryptBlocks(encrypted, padded)
	return iv, encrypted, nil
}

func pkcs7Unpad(data []byte) []byte {
	dataLength := len(data)
	padLength := int(data[dataLength-1])
	return data[:dataLength-padLength]
}

func Decrypt(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	cbcDecrypter := cipher.NewCBCDecrypter(block, iv)
	cbcDecrypter.CryptBlocks(decrypted, data)
	return pkcs7Unpad(decrypted), nil
}
