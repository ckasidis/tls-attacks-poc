package beast

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ckasidis/tls-attacks-poc/aescbc"
	"github.com/ckasidis/tls-attacks-poc/utils"
)

// Function to demonstrate a BEAST attack
func Attack(secret []byte) {
	var retrievedSecret []byte
	// Generate key and initial iv
	key, iv := aescbc.GenRandomKeys()
	// Pad 15 bytes, so we only have to guess the last byte
	padding := 15
	paddingBytes := []byte(strings.Repeat("#", padding))
	lengthBlock := 16
	t := 0
	// Loop until full secret is retrieved
	for t < len(secret) {
		// Guess byte 0 to 255
		for i := 0; i < 256; i++ {
			// Check negative padding and adjust s
			var s []byte
			if padding < 0 {
				s = secret[-padding:]
			} else {
				s = secret
			}
			// Attacker injects 15 bytes of padding to the plain text
			var input []byte
			if padding < 0 {
				input = s
			} else {
				input = append(bytes.Repeat([]byte("#"), padding), s...)
			}
			// Attacker send first request and save last block (C1n)
			firstRequest := aescbc.Encrypt([]byte(input), key, iv)
			firstRequestLastBlock := firstRequest[len(firstRequest)-lengthBlock:]
			// Attacker send second request and save last block (C2n)
			secondRequest := aescbc.Encrypt([]byte(input), key, firstRequestLastBlock)
			secondRequestLastBlock := secondRequest[len(secondRequest)-lengthBlock:]
			// Attacker save C2
			original := aescbc.SplitBlocks([]byte(hex.EncodeToString(secondRequest)), aescbc.BlockSizeHex)
			// Attacker guess last byte of first block
			guess := append(paddingBytes, byte(i))
			// Attacker use P = C1n XOR C2n XOR (XXXX XXXX XXXX XXXT) for third request
			xored := utils.XorBytes(secondRequestLastBlock, firstRequestLastBlock, guess)
			thirdRequest := aescbc.Encrypt(xored, key, secondRequestLastBlock)
			// Attacker save C3
			result := aescbc.SplitBlocks([]byte(hex.EncodeToString(thirdRequest)), aescbc.BlockSizeHex)
			// Attacker compare C2_0 with C3_0
			// C2_0 = Ek(C1_n XOR (XXXX XXXX XXXX XXXT))
			// P = C1_n XOR C2_n XOR (XXXX XXXX XXXX XXXT)
			// C3_0 = Ek(C2_n XOR P)
			// C3_0 = Ek(C2_n XOR C1_n XOR C2_n XOR (XXXX XXXX XXXX XXXT))
			// C3_0 = Ek(C1_n XOR (XXXX XXXX XXXX XXXT))
			// if C2_0 and C3_0 is equal, the guessed byte T is correct
			if bytes.Equal(result[0], original[0]) {
				fmt.Printf("%s == %s - ", original[0], result[0])
				fmt.Fprintf(os.Stdout, "Found byte %s%c%s\n", utils.ColorCyan, i, utils.ColorNone)
				paddingBytes = guess[1:]
				padding--
				retrievedSecret = append(retrievedSecret, byte(i))
				t++
				break
			} else if i == 255 {
				fmt.Println("Unable to find the char...")
			}
		}
	}
	// Print retrieved secret without padding
	fmt.Println()
	fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorRed, "Retrieved Secret from BEAST attack:", utils.ColorNone)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorCyan, retrievedSecret, utils.ColorNone)
}
