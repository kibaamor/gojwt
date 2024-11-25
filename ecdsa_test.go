//go:build test || unit

package gojwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
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
			t.Parallel()
			require := require.New(t)

			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(err)
			publicKey := &privateKey.PublicKey

			signer, err := NewECDSASigner(tt.id, tt.name, privateKey)
			require.NoError(err)
			require.Equal(tt.id, signer.ID())
			require.Equal(tt.name, signer.Name())

			verifier := signer.Verifier()
			require.Equal(tt.id, verifier.ID())
			require.Equal(tt.name, verifier.Name())

			verifier, err = NewECDSAVerifier(tt.id, tt.name, publicKey)
			require.NoError(err)
			require.Equal(tt.id, verifier.ID())
			require.Equal(tt.name, verifier.Name())
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
			privateKey: ecdsaP256PrivateKeyForTest,
			publicKey:  ecdsaP256PublicKeyForTest,
		},
		{
			id:         "es384",
			name:       "ES384",
			privateKey: ecdsaP384PrivateKeyForTest,
			publicKey:  ecdsaP384PublicKeyForTest,
		},
		{
			id:         "es512",
			name:       "ES512",
			privateKey: ecdsaP521PrivateKeyForTest,
			publicKey:  ecdsaP521PublicKeyForTest,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			signer, err := NewECDSASigner(tt.id, tt.name, tt.privateKey)
			require.NoError(err)

			data := []byte(tt.name)

			sig, err := signer.Sign(data)
			require.NoError(err)

			verifier, err := NewECDSAVerifier(tt.id, tt.name, tt.publicKey)
			require.NoError(err)
			err = verifier.Verify(data, sig)
			require.NoError(err)

			verifier = signer.Verifier()
			err = verifier.Verify(data, sig)
			require.NoError(err)
		})
	}
}
