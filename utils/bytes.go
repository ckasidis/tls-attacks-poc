package utils

// Function to reverse a byte slice
func ReverseBytes(bs []byte) []byte {
	tmp := make([]byte, len(bs))
	copy(tmp, bs)
	for i, j := 0, len(tmp)-1; i < j; i, j = i+1, j-1 {
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	return tmp
}

// Function to XOR byte slices
func XorBytes(x, y, z []byte) []byte {
	minLength := min(len(x), len(y), len(z))
	result := make([]byte, minLength)

	for i := 0; i < minLength; i++ {
		result[i] = x[i] ^ y[i] ^ z[i]
	}

	return result
}

// Function to find min int
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
