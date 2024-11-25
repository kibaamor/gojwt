//go:build test || unit

package gojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func genECDSAKeyBytes(curve elliptic.Curve, isPrivate, privateIsPKCS, pemEncoded bool) (*ecdsa.PrivateKey, []byte) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	var data []byte

	if isPrivate {
		if privateIsPKCS {
			data, err = x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				panic(err)
			}
		} else {
			data, err = x509.MarshalECPrivateKey(privateKey)
			if err != nil {
				panic(err)
			}
		}
	} else {
		data, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			panic(err)
		}
	}

	if pemEncoded {
		block := &pem.Block{
			Bytes: data,
		}
		if isPrivate {
			block.Type = "EC PRIVATE KEY"
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

func TestParseECDSAPrivateKeyFromBytesOrBase64(t *testing.T) {
	tests := []struct {
		name          string
		curve         elliptic.Curve
		privateIsPKCS bool
		testBase64    bool
	}{
		{
			name:          "P256 with base64 in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: true,
			testBase64:    true,
		},
		{
			name:          "P256 with base64 not in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: false,
			testBase64:    true,
		},
		{
			name:          "P256 without base64 in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: true,
			testBase64:    false,
		},
		{
			name:          "P256 without base64 not in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: false,
			testBase64:    false,
		},
		{
			name:          "P384 with base64 in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: true,
			testBase64:    true,
		},
		{
			name:          "P384 with base64 not in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: false,
			testBase64:    true,
		},
		{
			name:          "P384 without base64 in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: true,
			testBase64:    false,
		},
		{
			name:          "P384 without base64 not in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: false,
			testBase64:    false,
		},
		{
			name:          "P521 with base64 in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: true,
			testBase64:    true,
		},
		{
			name:          "P521 with base64 not in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: false,
			testBase64:    true,
		},
		{
			name:          "P521 without base64 in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: true,
			testBase64:    false,
		},
		{
			name:          "P521 without base64 not in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: false,
			testBase64:    false,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			privateKey, data := genECDSAKeyBytes(tt.curve, true, tt.privateIsPKCS, false)

			var (
				parsedPrivateKey *ecdsa.PrivateKey
				err              error
			)
			if tt.testBase64 {
				parsedPrivateKey, err = ParseECDSAPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(data))
			} else {
				parsedPrivateKey, err = ParseECDSAPrivateKeyFromBytes(data)
			}

			require.NoError(err)
			require.True(privateKey.Equal(parsedPrivateKey), "private key parsed failed")
		})
	}
}

func TestParseECDSAPublicKeyFromBytesOrBase64(t *testing.T) {
	tests := []struct {
		name       string
		curve      elliptic.Curve
		testBase64 bool
	}{
		{
			name:       "P256 with base64",
			curve:      elliptic.P256(),
			testBase64: true,
		},
		{
			name:       "P256 without base64",
			curve:      elliptic.P256(),
			testBase64: false,
		},
		{
			name:       "P384 with base64",
			curve:      elliptic.P384(),
			testBase64: true,
		},
		{
			name:       "P384 without base64",
			curve:      elliptic.P384(),
			testBase64: false,
		},
		{
			name:       "P521 with base64",
			curve:      elliptic.P521(),
			testBase64: true,
		},
		{
			name:       "P521 without base64",
			curve:      elliptic.P521(),
			testBase64: false,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			privateKey, data := genECDSAKeyBytes(tt.curve, false, false, false)
			publicKey := &privateKey.PublicKey

			var (
				parsedPublicKey *ecdsa.PublicKey
				err             error
			)
			if tt.testBase64 {
				parsedPublicKey, err = ParseECDSAPublicKeyFromBase64(base64.StdEncoding.EncodeToString(data))
			} else {
				parsedPublicKey, err = ParseECDSAPublicKeyFromBytes(data)
			}

			require.NoError(err)
			require.True(publicKey.Equal(parsedPublicKey), "public key parsed failed")
		})
	}
}

func TestParseECDSAPrivateKeyFromPemBytesOrFile(t *testing.T) {
	tests := []struct {
		name          string
		curve         elliptic.Curve
		privateIsPKCS bool
		isFile        bool
	}{
		{
			name:          "P256 with file in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: true,
			isFile:        true,
		},
		{
			name:          "P256 with file not in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: false,
			isFile:        true,
		},
		{
			name:          "P256 without file in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: true,
			isFile:        false,
		},
		{
			name:          "P256 without file not in PKCS format",
			curve:         elliptic.P256(),
			privateIsPKCS: false,
			isFile:        false,
		},
		{
			name:          "P384 with file in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: true,
			isFile:        true,
		},
		{
			name:          "P384 with file not in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: false,
			isFile:        true,
		},
		{
			name:          "P384 without file in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: true,
			isFile:        false,
		},
		{
			name:          "P384 without file not in PKCS format",
			curve:         elliptic.P384(),
			privateIsPKCS: false,
			isFile:        false,
		},
		{
			name:          "P521 with file in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: true,
			isFile:        true,
		},
		{
			name:          "P521 with file not in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: false,
			isFile:        true,
		},
		{
			name:          "P521 without file in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: true,
			isFile:        false,
		},
		{
			name:          "P521 without file not in PKCS format",
			curve:         elliptic.P521(),
			privateIsPKCS: false,
			isFile:        false,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			privateKey, data := genECDSAKeyBytes(tt.curve, true, tt.privateIsPKCS, true)

			var (
				parsedPrivateKey *ecdsa.PrivateKey
				err              error
			)
			if tt.isFile {
				var filename string
				filename, err = WriteToTempFile("", "ecdsa_test", data)
				require.NoError(err)
				parsedPrivateKey, err = ParseECDSAPrivateKeyFromPemFile(filename)
				_ = os.Remove(filename)
			} else {
				parsedPrivateKey, err = ParseECDSAPrivateKeyFromPemBytes(data)
			}

			require.NoError(err)
			require.True(privateKey.Equal(parsedPrivateKey), "private key parsed failed")
		})
	}
}

func TestParseECDSAPublicKeyFromPemBytesOrFile(t *testing.T) {
	tests := []struct {
		name   string
		curve  elliptic.Curve
		isFile bool
	}{
		{
			name:   "P256 with file",
			curve:  elliptic.P256(),
			isFile: true,
		},
		{
			name:   "P256 without file",
			curve:  elliptic.P256(),
			isFile: false,
		},
		{
			name:   "P384 with file",
			curve:  elliptic.P384(),
			isFile: true,
		},
		{
			name:   "P384 without file",
			curve:  elliptic.P384(),
			isFile: false,
		},
		{
			name:   "P521 with file",
			curve:  elliptic.P521(),
			isFile: true,
		},
		{
			name:   "P521 without file",
			curve:  elliptic.P521(),
			isFile: false,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			privateKey, data := genECDSAKeyBytes(tt.curve, false, false, true)
			publicKey := &privateKey.PublicKey

			var (
				parsedPublicKey *ecdsa.PublicKey
				err             error
			)
			if tt.isFile {
				var filename string
				filename, err = WriteToTempFile("", "ecdsa_test", data)
				require.NoError(err)
				parsedPublicKey, err = ParseECDSAPublicKeyFromPemFile(filename)
				_ = os.Remove(filename)
			} else {
				parsedPublicKey, err = ParseECDSAPublicKeyFromPemBytes(data)
			}

			require.NoError(err)
			require.True(publicKey.Equal(parsedPublicKey), "public key parsed failed")
		})
	}
}
