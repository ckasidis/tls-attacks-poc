package utils

import (
	"bytes"
)

// Function to split a byte slice to equal blocks
func SplitBlocks(sequence []byte, size int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(sequence); i += size {
		end := i + size
		if end > len(sequence) {
			end = len(sequence)
		}
		chunks = append(chunks, sequence[i:end])
	}
	return chunks
}

// Function to reverse byte slice
func ReverseByteSlice(bs []byte) []byte {
	tmp := make([]byte, len(bs))
	copy(tmp, bs)
	for i, j := 0, len(tmp)-1; i < j; i, j = i+1, j-1 {
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	return tmp
}

// Function to pad P for AES
func Pad(text []byte) []byte {
	// Calculate how many bytes of padding are needed
	paddingRequired := BlockSize - len(text)%BlockSize
	// Fill padding bytes
	padding := bytes.Repeat([]byte{byte(paddingRequired)}, paddingRequired)
	// Return padded text
	return append(text, padding...)
}
