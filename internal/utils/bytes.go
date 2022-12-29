package utils

import (
	"crypto/rand"
)

func RandBytes(n int) []byte {
	if n <= 0 {
		return nil
	}

	bs := make([]byte, n)
	_, err := rand.Read(bs)
	if err != nil {
		panic(err)
	}
	return bs
}
