package util

import "encoding/base64"

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
