//go:build test || unit

package gojwt

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESCBCCipher_NameKeySizeIVSize(t *testing.T) {
	tests := []struct {
		id      string
		name    string
		keySize int
		ivSize  int
	}{
		{
			id:      "a128cbc",
			name:    "A128CBC",
			keySize: 16,
			ivSize:  16,
		},
		{
			id:      "a192cbc",
			name:    "A192CBC",
			keySize: 24,
			ivSize:  16,
		},
		{
			id:      "a256cbc",
			name:    "A256CBC",
			keySize: 32,
			ivSize:  16,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			key := RandBytes(tt.keySize)
			c, err := NewAESCBCCipher(tt.id, key)
			require.NoError(err)
			require.Equal(tt.id, c.ID())
			require.Equal(tt.name, c.Name())
			require.Equal(tt.keySize, c.KeySize())
			require.Equal(tt.ivSize, c.IVSize())
		})
	}
}

func TestAesCBCCipher_EncryptDecrypt(t *testing.T) {
	// http://www.metools.info/enencrypt/aes276.html
	// https://the-x.cn/cryptography/Aes.aspx
	tests := []struct {
		id   string
		name string
		key  string
		data string
		want string
	}{
		{
			id:   "a128cbc without padding",
			name: "A128CBC",
			key:  "kibazencnA128CBC",
			data: "nopaddingkibazen",
			want: "i5oLo8cHB/1Si0j95KKmDfb0Z8gs70YS5tMTQwT7rZ4=",
		},
		{
			id:   "a128cbc with padding",
			name: "A128CBC",
			key:  "kibazencnA128CBC",
			data: "paddingtest",
			want: "/GzNMMawp2X/OXyhqnVeVw==",
		},
		{
			id:   "a192cbc without padding",
			name: "A192CBC",
			key:  "kibazencnA192CBCnA192CBC",
			data: "nopaddingkibazen",
			want: "BQKfa8jVAK2VKTYaMlOwt+cqxDMf+oeyitGVtX2GGrk=",
		},
		{
			id:   "a192cbc with padding",
			name: "A192CBC",
			key:  "kibazencnA192CBCnA192CBC",
			data: "paddingtest",
			want: "vji+9nKQzND9Tin82Omxlw==",
		},
		{
			id:   "a256cbc without padding",
			name: "A256CBC",
			key:  "kibazencnA256CBCkibazencnA256CBC",
			data: "nopaddingkibazen",
			want: "eYymdkliuCG3aPzucOWzwmIVXzTWpUzmcUoZci88ZLs=",
		},
		{
			id:   "a256cbc with padding",
			name: "A256CBC",
			key:  "kibazencnA256CBCkibazencnA256CBC",
			data: "paddingtest",
			want: "mJHsVEW9b+RWVQNa6jI8Fg==",
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			c, err := NewAESCBCCipher(tt.id, []byte(tt.key))
			require.NoError(err)
			require.Equal(tt.name, c.Name())

			data := []byte(tt.data)

			encryptedData, err := c.Encrypt(data, iv)
			require.NoError(err)

			encryptedDataB64 := base64.StdEncoding.EncodeToString(encryptedData)
			require.Equal(tt.want, encryptedDataB64)

			decryptedData, err := c.Decrypt(encryptedData, iv)
			require.NoError(err)

			require.Equal(data, decryptedData)
		})
	}
}
