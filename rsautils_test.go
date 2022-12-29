//go:build test || unit

package gojwt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/kibaamor/gojwt/internal/utils"

	"github.com/stretchr/testify/assert"
)

func genRSAKeyBytes(isPrivate, isPKCS1, pemEncoded bool) (privateKey *rsa.PrivateKey, data []byte) {
	var err error

	privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	if isPrivate {
		if isPKCS1 {
			data = x509.MarshalPKCS1PrivateKey(privateKey)
		} else {
			data, err = x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				panic(err)
			}
		}
	} else {
		if isPKCS1 {
			data = x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
		} else {
			data, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				panic(err)
			}
		}
	}

	if pemEncoded {
		block := &pem.Block{
			Bytes: data,
		}
		if isPrivate {
			block.Type = "RSA PRIVATE KEY"
		} else {
			block.Type = "PUBLIC KEY"
		}

		var b bytes.Buffer
		err = pem.Encode(&b, block)
		if err != nil {
			panic(err)
		}
		data = b.Bytes()
	}

	return privateKey, data
}

func TestParseRSAPrivateKeyFromBytesOrBase64(t *testing.T) {
	tests := []struct {
		name       string
		isPKCS1    bool
		testBase64 bool
	}{
		{
			name:       "PKCS1 with base64",
			isPKCS1:    true,
			testBase64: true,
		},
		{
			name:       "PKCS1 without base64",
			isPKCS1:    true,
			testBase64: false,
		},
		{
			name:       "PKCS8 with base64",
			isPKCS1:    false,
			testBase64: true,
		},
		{
			name:       "PKCS8 without base64",
			isPKCS1:    false,
			testBase64: true,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, data := genRSAKeyBytes(true, tt.isPKCS1, false)

			var (
				parsedPrivateKey *rsa.PrivateKey
				err              error
			)
			if tt.testBase64 {
				parsedPrivateKey, err = ParseRSAPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(data))
			} else {
				parsedPrivateKey, err = ParseRSAPrivateKeyFromBytes(data)
			}

			assert.Nil(t, err)
			assert.True(t, privateKey.Equal(parsedPrivateKey), "private key parsed failed")
		})
	}
}

func TestParseRSAPublicKeyFromBytesOrBase64(t *testing.T) {
	tests := []struct {
		name       string
		isPKCS1    bool
		testBase64 bool
	}{
		{
			name:       "PKCS1 with base64",
			isPKCS1:    true,
			testBase64: true,
		},
		{
			name:       "PKCS1 without base64",
			isPKCS1:    true,
			testBase64: false,
		},
		{
			name:       "PKIX with base64",
			isPKCS1:    false,
			testBase64: true,
		},
		{
			name:       "PKIX without base64",
			isPKCS1:    false,
			testBase64: true,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, data := genRSAKeyBytes(false, tt.isPKCS1, false)
			publicKey := &privateKey.PublicKey

			var (
				parsedPublicKey *rsa.PublicKey
				err             error
			)
			if tt.testBase64 {
				parsedPublicKey, err = ParseRSAPublicKeyFromBase64(base64.StdEncoding.EncodeToString(data))
			} else {
				parsedPublicKey, err = ParseRSAPublicKeyFromBytes(data)
			}

			assert.Nil(t, err)
			assert.True(t, publicKey.Equal(parsedPublicKey), "public key parsed failed")
		})
	}
}

func TestParseRSAPrivateKeyFromPemBytesOrFile(t *testing.T) {
	tests := []struct {
		name    string
		isPKCS1 bool
		isFile  bool
	}{
		{
			name:    "PKCS1 with file",
			isPKCS1: true,
			isFile:  true,
		},
		{
			name:    "PKCS1 without file",
			isPKCS1: true,
			isFile:  false,
		},
		{
			name:    "PKCS8 with file",
			isPKCS1: false,
			isFile:  true,
		},
		{
			name:    "PKCS8 without file",
			isPKCS1: false,
			isFile:  true,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, data := genRSAKeyBytes(true, tt.isPKCS1, true)

			var (
				parsedPrivateKey *rsa.PrivateKey
				err              error
			)
			if tt.isFile {
				var filename string
				filename, err = utils.WriteToTempFile("", "rsa_test", data)
				assert.Nil(t, err)
				parsedPrivateKey, err = ParseRSAPrivateKeyFromPemFile(filename)
				_ = os.Remove(filename)
			} else {
				parsedPrivateKey, err = ParseRSAPrivateKeyFromPemBytes(data)
			}

			assert.Nil(t, err)
			assert.True(t, privateKey.Equal(parsedPrivateKey), "private key parsed failed")
		})
	}
}

func TestParseRSAPublicKeyFromPemBytesOrFile(t *testing.T) {
	tests := []struct {
		name    string
		isPKCS1 bool
		isFile  bool
	}{
		{
			name:    "PKCS1 with file",
			isPKCS1: true,
			isFile:  true,
		},
		{
			name:    "PKCS1 without file",
			isPKCS1: true,
			isFile:  false,
		},
		{
			name:    "PKCS8 with file",
			isPKCS1: false,
			isFile:  true,
		},
		{
			name:    "PKCS8 without file",
			isPKCS1: false,
			isFile:  false,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, data := genRSAKeyBytes(false, tt.isPKCS1, true)
			publicKey := &privateKey.PublicKey

			var (
				parsedPublicKey *rsa.PublicKey
				err             error
			)
			if tt.isFile {
				var filename string
				filename, err = utils.WriteToTempFile("", "rsa_test", data)
				assert.Nil(t, err)
				parsedPublicKey, err = ParseRSAPublicKeyFromPemFile(filename)
				_ = os.Remove(filename)
			} else {
				parsedPublicKey, err = ParseRSAPublicKeyFromPemBytes(data)
			}

			assert.Nil(t, err)
			assert.True(t, publicKey.Equal(parsedPublicKey), "public key parsed failed")
		})
	}
}
