package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

//
// Contains the AES KEY, injected at build time.
// Key lenght MUST be 32 bytes
var (
	AesKeyString string
)

// Checks the key injected at build time, before anything else can use it.
// Without this check the first encrypt/decrypt call would build a nil cipher
// and panic instead of telling the user the build was made without -ldflags.
func validateKey() error {
	if len(AesKeyString) == 0 {
		return fmt.Errorf("AES key is empty: build h2s with -ldflags='-X main.AesKeyString=<key>' (see Makefile)")
	}

	if _, err := aes.NewCipher([]byte(AesKeyString)); err != nil {
		return fmt.Errorf("invalid AES key: %s (key lenght MUST be 32 bytes, got %d)", err.Error(), len(AesKeyString))
	}

	return nil
}

// encrypt encrypts a plain string with the secret key and returns the encoded string.
func encrypt(plainData string) (string, error) {
	cipherBlock, err := aes.NewCipher([]byte(AesKeyString))
	if err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	cipherBlock, err := aes.NewCipher([]byte(AesKeyString))
	if err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", fmt.Errorf("encrypted data is shorter than the nonce")
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		return "", err
	}

	return string(plainData), nil
}
