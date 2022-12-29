package gojwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

var (
	errRSAPublicKey  = errors.New("gojwt/rsa: invalid public key")
	errRSAPrivateKey = errors.New("gojwt/rsa: invalid private key")

	rsaPSSVerifyOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	rsaPSSSignOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
)

type rsaVerifier struct {
	isPSS     bool
	id        string
	name      string
	hash      crypto.Hash
	publicKey *rsa.PublicKey
}

func (s *rsaVerifier) ID() string {
	return s.id
}

func (s *rsaVerifier) Name() string {
	return s.name
}

func (s *rsaVerifier) Verify(data, signature []byte) error {
	h := s.hash.New()
	_, err := h.Write(data)
	if err != nil {
		return err
	}

	if s.isPSS {
		return rsa.VerifyPSS(s.publicKey, s.hash, h.Sum(nil), signature, rsaPSSVerifyOptions)
	}
	return rsa.VerifyPKCS1v15(s.publicKey, s.hash, h.Sum(nil), signature)
}

type rsaSigner struct {
	rsaVerifier
	privateKey *rsa.PrivateKey
}

func (s *rsaSigner) Sign(data []byte) ([]byte, error) {
	h := s.hash.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	if s.isPSS {
		return rsa.SignPSS(rand.Reader, s.privateKey, s.hash, h.Sum(nil), rsaPSSSignOptions)
	}
	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, s.hash, h.Sum(nil))
}

func (s *rsaSigner) Verifier() Verifier {
	return s
}

func newRSAVerifierInternal(isPSS bool, id, name string, hash crypto.Hash, publicKey *rsa.PublicKey) (Verifier, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("gojwt/rsa: invalid hash '%v'", hash)
	}
	if publicKey == nil {
		return nil, errRSAPublicKey
	}
	return &rsaVerifier{
		isPSS:     isPSS,
		id:        id,
		name:      name,
		hash:      hash,
		publicKey: publicKey,
	}, nil
}

func newRSASignerInternal(isPSS bool, id, name string, hash crypto.Hash, privateKey *rsa.PrivateKey) (Signer, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("gojwt/rsa: invalid hash '%v'", hash)
	}
	if privateKey == nil {
		return nil, errRSAPrivateKey
	}
	err := privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("gojwt/rsa: invalid private key: '%w'", err)
	}
	return &rsaSigner{
		rsaVerifier: rsaVerifier{
			isPSS:     isPSS,
			id:        id,
			name:      name,
			hash:      hash,
			publicKey: &privateKey.PublicKey,
		},
		privateKey: privateKey,
	}, nil
}

func NewRS256Verifier(id string, publicKey *rsa.PublicKey) (Verifier, error) {
	return newRSAVerifierInternal(false, id, "RS256", crypto.SHA256, publicKey)
}
func NewRS256Signer(id string, privateKey *rsa.PrivateKey) (Signer, error) {
	return newRSASignerInternal(false, id, "RS256", crypto.SHA256, privateKey)
}

func NewRS384Verifier(id string, publicKey *rsa.PublicKey) (Verifier, error) {
	return newRSAVerifierInternal(false, id, "RS384", crypto.SHA384, publicKey)
}
func NewRS384Signer(id string, privateKey *rsa.PrivateKey) (Signer, error) {
	return newRSASignerInternal(false, id, "RS384", crypto.SHA384, privateKey)
}

func NewRS512Verifier(id string, publicKey *rsa.PublicKey) (Verifier, error) {
	return newRSAVerifierInternal(false, id, "RS512", crypto.SHA512, publicKey)
}
func NewRS512Signer(id string, privateKey *rsa.PrivateKey) (Signer, error) {
	return newRSASignerInternal(false, id, "RS512", crypto.SHA512, privateKey)
}

func NewPS256Verifier(id string, publicKey *rsa.PublicKey) (Verifier, error) {
	return newRSAVerifierInternal(true, id, "PS256", crypto.SHA256, publicKey)
}
func NewPS256Signer(id string, privateKey *rsa.PrivateKey) (Signer, error) {
	return newRSASignerInternal(true, id, "PS256", crypto.SHA256, privateKey)
}

func NewPS384Verifier(id string, publicKey *rsa.PublicKey) (Verifier, error) {
	return newRSAVerifierInternal(true, id, "PS384", crypto.SHA384, publicKey)
}
func NewPS384Signer(id string, privateKey *rsa.PrivateKey) (Signer, error) {
	return newRSASignerInternal(true, id, "PS384", crypto.SHA384, privateKey)
}

func NewPS512Verifier(id string, publicKey *rsa.PublicKey) (Verifier, error) {
	return newRSAVerifierInternal(true, id, "PS512", crypto.SHA512, publicKey)
}
func NewPS512Signer(id string, privateKey *rsa.PrivateKey) (Signer, error) {
	return newRSASignerInternal(true, id, "PS512", crypto.SHA512, privateKey)
}

func NewRSAVerifier(id string, name string, publicKey *rsa.PublicKey) (Verifier, error) {
	if name == "RS256" {
		return NewRS256Verifier(id, publicKey)
	} else if name == "RS384" {
		return NewRS384Verifier(id, publicKey)
	} else if name == "RS512" {
		return NewRS512Verifier(id, publicKey)
	} else if name == "PS256" {
		return NewPS256Verifier(id, publicKey)
	} else if name == "PS384" {
		return NewPS384Verifier(id, publicKey)
	} else if name == "PS512" {
		return NewPS512Verifier(id, publicKey)
	}
	return nil, fmt.Errorf("gojwt/rsa: invalid rsa verifier name '%v'", name)
}

func NewRSASigner(id string, name string, privateKey *rsa.PrivateKey) (Signer, error) {
	if name == "RS256" {
		return NewRS256Signer(id, privateKey)
	} else if name == "RS384" {
		return NewRS384Signer(id, privateKey)
	} else if name == "RS512" {
		return NewRS512Signer(id, privateKey)
	} else if name == "PS256" {
		return NewPS256Signer(id, privateKey)
	} else if name == "PS384" {
		return NewPS384Signer(id, privateKey)
	} else if name == "PS512" {
		return NewPS512Signer(id, privateKey)
	}
	return nil, fmt.Errorf("gojwt/rsa: invalid rsa signer name '%v'", name)
}
