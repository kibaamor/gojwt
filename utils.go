package gojwt

import (
	"crypto/rand"
	"encoding/base64"
	"os"
)

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
