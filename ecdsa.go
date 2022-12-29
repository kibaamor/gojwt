package gojwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var (
	errECDSAVerification = errors.New("gojwt/ecdsa: verification error")
	errECDSAPublicKey    = errors.New("gojwt/ecdsa: invalid public key")
	errECDSAPrivateKey   = errors.New("gojwt/ecdsa: invalid private key")
)

type ecdsaVerifier struct {
	id        string
	name      string
	hash      crypto.Hash
	keySize   int
	publicKey *ecdsa.PublicKey
}

func (s *ecdsaVerifier) ID() string {
	return s.id
}

func (s *ecdsaVerifier) Name() string {
	return s.name
}

func (s *ecdsaVerifier) Verify(data, signature []byte) error {
	if len(signature) != 2*s.keySize {
		return errECDSAVerification
	}

	h := s.hash.New()
	_, err := h.Write(data)
	if err != nil {
		return err
	}

	vr := big.NewInt(0).SetBytes(signature[:s.keySize])
	vs := big.NewInt(0).SetBytes(signature[s.keySize:])
	if !ecdsa.Verify(s.publicKey, h.Sum(nil), vr, vs) {
		return errECDSAVerification
	}
	return nil
}

type ecdsaSigner struct {
	ecdsaVerifier
	privateKey *ecdsa.PrivateKey
}

func (s *ecdsaSigner) Sign(data []byte) ([]byte, error) {
	h := s.hash.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	vr, vs, err := ecdsa.Sign(rand.Reader, s.privateKey, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 2*s.keySize)
	vr.FillBytes(signature[:s.keySize])
	vs.FillBytes(signature[s.keySize:])

	return signature, nil
}

func (s *ecdsaSigner) Verifier() Verifier {
	return s
}

func getECDSAKeySize(curveBits int) int {
	keySize := curveBits / 8
	if curveBits%8 > 0 {
		keySize++
	}
	return keySize
}

func newECDSAVerifierInternal(id, name string, hash crypto.Hash, publicKey *ecdsa.PublicKey, curveBits int, curveName string) (Verifier, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("gojwt/ecdsa: invalid hash '%v'", hash)
	}
	if publicKey == nil {
		return nil, errECDSAPublicKey
	}
	if curveBits != publicKey.Params().BitSize {
		return nil, fmt.Errorf("gojwt/ecdsa: invalid bit size. want: %v, got: %v", curveBits, publicKey.Params().BitSize)
	}
	if curveName != publicKey.Params().Name {
		return nil, fmt.Errorf("gojwt/ecdsa: invalid curve name. want: %v, got: %v", curveName, publicKey.Params().Name)
	}
	return &ecdsaVerifier{
		id:        id,
		name:      name,
		hash:      hash,
		keySize:   getECDSAKeySize(curveBits),
		publicKey: publicKey,
	}, nil
}

func newECDSASignerInternal(id, name string, hash crypto.Hash, privateKey *ecdsa.PrivateKey, curveBits int, curveName string) (Signer, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("gojwt/ecdsa: invalid hash '%v'", hash)
	}
	if privateKey == nil {
		return nil, errECDSAPrivateKey
	}
	if curveBits != privateKey.Params().BitSize {
		return nil, fmt.Errorf("gojwt/ecdsa: invalid bit size. want: %v, got: %v", curveBits, privateKey.Params().BitSize)
	}
	if curveName != privateKey.Params().Name {
		return nil, fmt.Errorf("gojwt/ecdsa: invalid curve name. want: %v, got: %v", curveName, privateKey.Params().Name)
	}
	return &ecdsaSigner{
		ecdsaVerifier: ecdsaVerifier{
			id:        id,
			name:      name,
			hash:      hash,
			keySize:   getECDSAKeySize(curveBits),
			publicKey: &privateKey.PublicKey,
		},
		privateKey: privateKey,
	}, nil
}

func NewES256Verifier(id string, publicKey *ecdsa.PublicKey) (Verifier, error) {
	return newECDSAVerifierInternal(id, "ES256", crypto.SHA256, publicKey, 256, "P-256")
}
func NewES256Signer(id string, privateKey *ecdsa.PrivateKey) (Signer, error) {
	return newECDSASignerInternal(id, "ES256", crypto.SHA256, privateKey, 256, "P-256")
}

func NewES384Verifier(id string, publicKey *ecdsa.PublicKey) (Verifier, error) {
	return newECDSAVerifierInternal(id, "ES384", crypto.SHA384, publicKey, 384, "P-384")
}
func NewES384Signer(id string, privateKey *ecdsa.PrivateKey) (Signer, error) {
	return newECDSASignerInternal(id, "ES384", crypto.SHA384, privateKey, 384, "P-384")
}

func NewES512Verifier(id string, publicKey *ecdsa.PublicKey) (Verifier, error) {
	return newECDSAVerifierInternal(id, "ES512", crypto.SHA512, publicKey, 521, "P-521")
}
func NewES512Signer(id string, privateKey *ecdsa.PrivateKey) (Signer, error) {
	return newECDSASignerInternal(id, "ES512", crypto.SHA512, privateKey, 521, "P-521")
}

func NewECDSAVerifier(id, name string, publicKey *ecdsa.PublicKey) (Verifier, error) {
	if name == "ES256" {
		return NewES256Verifier(id, publicKey)
	} else if name == "ES384" {
		return NewES384Verifier(id, publicKey)
	} else if name == "ES512" {
		return NewES512Verifier(id, publicKey)
	}
	return nil, fmt.Errorf("gojwt/ecdsa: invalid ecdsa verifier name '%v'", name)
}

func NewECDSASigner(id, name string, privateKey *ecdsa.PrivateKey) (Signer, error) {
	if name == "ES256" {
		return NewES256Signer(id, privateKey)
	} else if name == "ES384" {
		return NewES384Signer(id, privateKey)
	} else if name == "ES512" {
		return NewES512Signer(id, privateKey)
	}
	return nil, fmt.Errorf("gojwt/ecdsa: invalid ecdsa verifier name '%v'", name)
}
