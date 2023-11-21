package utils

import (
	"crypto/aes"
)

const (
	ColorNone = "\033[0m"
	ColorRed  = "\033[0;31m"
	ColorCyan = "\033[36m"
	BlockSize = aes.BlockSize
)
