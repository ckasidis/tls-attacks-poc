package poodle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ckasidis/tls-attacks-poc/aescbc"
	"github.com/ckasidis/tls-attacks-poc/utils"
)

// Function to print tampered request
func printTamperedRequest(request [][]byte, replaced int) {
	for i, b := range request {
		if i == replaced || i == len(request)-1 {
			fmt.Fprintf(os.Stdout, "%s%s%s", utils.ColorCyan, b, utils.ColorNone)
		} else {
			fmt.Printf("%s", b)
		}
	}
	fmt.Println()
}

// Function to adjust padding for POODLE attack
func adjustPadding(plainText []byte) (int, int) {
	// Encrypt secret
	key, iv := aescbc.GenRandomKeys()
	encryptedSecret := aescbc.Encrypt(plainText, key, iv)
	originalLength := len(hex.EncodeToString(encryptedSecret))
	// Adjust padding so last block is full of padding
	padding := 1
	for {
		paddedSecret := aescbc.Encrypt(append(bytes.Repeat([]byte{'a'}, padding), []byte(plainText)...), key, iv)
		newLength := len(hex.EncodeToString(paddedSecret))
		// New block: last block is full of padding
		if newLength > originalLength {
			break
		}
		padding++
	}
	return originalLength, padding
}

// Function to demonstrate a POODLE attack
func Attack(secret []byte) {
	var blockSecret []byte
	var retrievedBlockSecrets []string
	// Calculate extra padding required for POODLE attack and get original length in hex
	originalLength, padding := adjustPadding(secret)
	initialPadding := padding
	// Loop through each block that contains the secret
	for block := originalLength/aescbc.BlockSizeHex - 2; block > 0; block-- {
		// Loop through each char in the block
		for char := 0; char < aescbc.BlockSize; char++ {
			// Count number of guesses
			count := 0
			for {
				key, iv := aescbc.GenRandomKeys()
				// % = dummy bytes before padding, # = padding, $ = dummy bytes after secret
				paddedInput := fmt.Sprintf("%s%s%s%s", bytes.Repeat([]byte("%"), aescbc.BlockSize), bytes.Repeat([]byte("#"), padding), secret, bytes.Repeat([]byte("$"), block*aescbc.BlockSize-char))
				encrypted := aescbc.Encrypt([]byte(paddedInput), key, iv)
				request := aescbc.SplitBlocks([]byte(hex.EncodeToString(encrypted)), aescbc.BlockSizeHex)
				// Change the last block with a block we want to attack
				request[len(request)-1] = request[block]
				// Join the blocks for decryption
				cipher, _ := hex.DecodeString(string(bytes.Join(request, nil)))
				_, err := aescbc.Decrypt(cipher, key, iv)
				count++
				// If there is no error, attacker can decipher the last byte
				if err == nil {
					// Update the padding to reveal the next byte
					padding++
					// Cn-1
					Cn1 := request[len(request)-2]
					// Ci-1
					Ci1 := request[block-1]
					Cn1LastByte, _ := hex.DecodeString(string(Cn1[len(Cn1)-2:]))
					Ci1LastByte, _ := hex.DecodeString(string(Ci1[len(Ci1)-2:]))
					// Decipher a byte
					// Pn = D(Cn) XOR Cn-1
					// Pn = D(Ci) XOR Cn-1
					// (XXXX XXXX XXXX XXXF) = D(Ci) XOR Cn-1
					// (XXXX XXXX XXXX XXXF) = Pi XOR Ci-1 XOR Cn-1
					// Pi = (XXXX XXXX XXXX XXXF) XOR Ci-1 XOR Cn-1
					decipheredByte := 0x0f ^ Ci1LastByte[0] ^ Cn1LastByte[0]
					// Update block secret
					blockSecret = append(blockSecret, decipheredByte)
					// Reverse block secret and print to console
					secretReversed := utils.ReverseBytes(blockSecret)
					// print tampered request
					fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorRed, "Tampered Request:", utils.ColorNone)
					printTamperedRequest(request, block)
					// print deciphered byte
					fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorRed, "Retrieved Block Secret:", utils.ColorNone)
					fmt.Fprintf(os.Stdout, "Deciphered Byte: %s%s%s\n", utils.ColorCyan, string(decipheredByte), utils.ColorNone)
					fmt.Fprintf(os.Stdout, "Secret Retrieved from Block %d: [%s%16s%s]\n", block, utils.ColorCyan, bytes.ToUpper(secretReversed), utils.ColorNone)
					fmt.Println()
					break
				}
			}
		}
		// Save block secret
		blockSecret = utils.ReverseBytes(blockSecret)
		retrievedBlockSecrets = append([]string{string(blockSecret)}, retrievedBlockSecrets...)
		// Reset block secret
		blockSecret = []byte{}
		// Reset padding
		padding = initialPadding
	}
	// Join all block secrets to reveal obtained secret
	retrievedSecret := strings.Join(retrievedBlockSecrets, "")
	// Remove padding
	retrievedSecret = strings.ReplaceAll(retrievedSecret, "#", "")
	// Print retrieved secret without padding
	fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorRed, "Retrieved Secret from POODLE attack:", utils.ColorNone)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorCyan, retrievedSecret, utils.ColorNone)
}
