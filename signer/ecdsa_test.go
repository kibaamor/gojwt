//go:build test || unit

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kibaamor/gojwt/internal/test"
)

func TestNewECDSASignerAndVerifier(t *testing.T) {
	tests := []struct {
		id    string
		name  string
		curve elliptic.Curve
	}{
		{
			id:    "es256",
			name:  "ES256",
			curve: elliptic.P256(),
		},
		{
			id:    "es384",
			name:  "ES384",
			curve: elliptic.P384(),
		},
		{
			id:    "es512",
			name:  "ES512",
			curve: elliptic.P521(),
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			assert.Nil(t, err)
			publicKey := &privateKey.PublicKey

			signer, err := NewECDSASigner(tt.id, tt.name, privateKey)
			assert.Nil(t, err)
			assert.Equal(t, tt.id, signer.ID())
			assert.Equal(t, tt.name, signer.Name())

			verifier := signer.Verifier()
			assert.Equal(t, tt.id, verifier.ID())
			assert.Equal(t, tt.name, verifier.Name())

			verifier, err = NewECDSAVerifier(tt.id, tt.name, publicKey)
			assert.Nil(t, err)
			assert.Equal(t, tt.id, verifier.ID())
			assert.Equal(t, tt.name, verifier.Name())
		})
	}
}

func TestECDSASignerAndVerifier(t *testing.T) {
	tests := []struct {
		id         string
		name       string
		privateKey *ecdsa.PrivateKey
		publicKey  *ecdsa.PublicKey
	}{
		{
			id:         "es256",
			name:       "ES256",
			privateKey: test.ECDSAP256PrivateKey,
			publicKey:  test.ECDSAP256PublicKey,
		},
		{
			id:         "es384",
			name:       "ES384",
			privateKey: test.ECDSAP384PrivateKey,
			publicKey:  test.ECDSAP384PublicKey,
		},
		{
			id:         "es512",
			name:       "ES512",
			privateKey: test.ECDSAP521PrivateKey,
			publicKey:  test.ECDSAP521PublicKey,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewECDSASigner(tt.id, tt.name, tt.privateKey)
			assert.Nil(t, err)

			data := []byte(tt.name)

			sig, err := signer.Sign(data)
			assert.Nil(t, err)

			verifier, err := NewECDSAVerifier(tt.id, tt.name, tt.publicKey)
			assert.Nil(t, err)
			err = verifier.Verify(data, sig)
			assert.Nil(t, err)

			verifier = signer.Verifier()
			err = verifier.Verify(data, sig)
			assert.Nil(t, err)
		})
	}
}
