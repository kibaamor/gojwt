package util

import (
	"bytes"
	"errors"
)

var errPKCS7Padding = errors.New("util/pkcs7: invalid padding")

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func PKCS7Unpadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errPKCS7Padding
	}

	padding := int(data[len(data)-1])
	if len(data) < padding {
		return nil, errPKCS7Padding
	}

	// make sure the values of all padding bytes are equal to 'padding'
	for i := len(data) - padding + 1; i < len(data); i++ {
		if data[i-1] != data[i] {
			return nil, errPKCS7Padding
		}
	}

	return data[:len(data)-padding], nil
}
