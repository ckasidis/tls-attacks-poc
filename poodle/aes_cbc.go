package poodle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"

	"github.com/ckasidis/tls-attacks-poc/utils"
)

// Function to generate a random key and iv
func genRandomKeys() ([]byte, []byte) {
	// Generate a random Key for AES
	key := make([]byte, utils.BlockSize)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	// Generate a random Initialization Vector for AES
	iv := make([]byte, utils.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}
	// Return key, iv
	return key, iv
}

// Function to verify the padded text and return data
func verify(paddedText, key []byte) ([]byte, error) {
	// Get last byte value
	lastByteValue := int(paddedText[len(paddedText)-1])
	// Check index out of range
	hashLength := 32
	if len(paddedText)-1-lastByteValue-hashLength < 0 {
		return nil, errors.New("Index out of range")
	}
	// Get data and hmac checksum
	data := paddedText[:len(paddedText)-1-lastByteValue-hashLength]
	hash := paddedText[len(data) : len(paddedText)-1-lastByteValue]
	// Verify hash
	h := hmac.New(sha256.New, key)
	h.Write(data)
	newHash := h.Sum(nil)
	if !bytes.Equal(hash, newHash) {
		return nil, errors.New("hashes are not the same!")
	}
	// Return data
	return data, nil
}

// Function to encrypt plain text in SSL 3.0
func encrypt(plainText, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	// Convert data to byte slice
	data := []byte(plainText)
	// Calculate hmac checksum
	h := hmac.New(sha256.New, key)
	h.Write(data)
	hash := h.Sum(nil)
	// Append checksum to data
	text := append(data, hash...)
	paddedText := utils.Pad(text)
	// Encrypt plain text
	cipherText := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedText)
	// Return cipher text
	return cipherText
}

// Function to decrypt cipher text in SSL 3.0
func decrypt(cipherText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Decrypt cipher text
	paddedText := make([]byte, len(cipherText))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(paddedText, cipherText)
	// Verify hash and get plain text
	plaintext, err := verify(paddedText, key)
	if err != nil {
		return nil, err
	}
	// Return plain text
	return plaintext, nil
}
