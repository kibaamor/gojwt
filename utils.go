package gojwt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
)

var errPKCS7Padding = errors.New("gojwt/pkcs7: invalid padding")

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

func RawURLEncode(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	enc := base64.RawURLEncoding
	dst := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(dst, src)
	return dst
}

func RawURLDecode(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}

	enc := base64.RawURLEncoding
	dst := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(dst, src)
	return dst[:n], err
}

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

func WriteToTempFile(dir, pattern string, data []byte) (filename string, err error) {
	var f *os.File
	f, err = os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}

	_, err = f.Write(data)
	if err != nil {
		return "", err
	}

	filename = f.Name()

	err = f.Close()
	if err != nil {
		_ = os.Remove(f.Name())
	}

	return filename, err
}

func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
