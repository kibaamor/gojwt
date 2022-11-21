package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

var (
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

func (s *rsaVerifier) Id() string {
	return s.id
}

func (s *rsaVerifier) Name() string {
	return s.name
}

func (s *rsaVerifier) Verify(data, signature []byte) error {
	h := s.hash.New()
	h.Write(data)
	if s.isPSS {
		return rsa.VerifyPSS(s.publicKey, s.hash, h.Sum(nil), signature, rsaPSSVerifyOptions)
	} else {
		return rsa.VerifyPKCS1v15(s.publicKey, s.hash, h.Sum(nil), signature)
	}
}

type rsaSigner struct {
	rsaVerifier
	privateKey *rsa.PrivateKey
}

func (s *rsaSigner) Sign(data []byte) ([]byte, error) {
	h := s.hash.New()
	h.Write(data)
	if s.isPSS {
		return rsa.SignPSS(rand.Reader, s.privateKey, s.hash, h.Sum(nil), rsaPSSSignOptions)
	} else {
		return rsa.SignPKCS1v15(rand.Reader, s.privateKey, s.hash, h.Sum(nil))
	}
}

func (s *rsaSigner) Verifier() Verifier {
	return s
}

func newRSAVerifier(isPSS bool, id, name string, hash crypto.Hash, publicKey *rsa.PublicKey) Verifier {
	if !hash.Available() {
		panic(fmt.Sprintf("signer/rsa: invalid hash '%v'", hash))
	}
	if publicKey == nil {
		panic("signer/rsa: invalid public key")
	}
	return &rsaVerifier{
		isPSS:     isPSS,
		id:        id,
		name:      name,
		hash:      hash,
		publicKey: publicKey,
	}
}

func newRSASigner(isPSS bool, id, name string, hash crypto.Hash, privateKey *rsa.PrivateKey) Signer {
	if !hash.Available() {
		panic(fmt.Sprintf("signer/rsa: invalid hash '%v'", hash))
	}
	if privateKey == nil {
		panic("signer/rsa: invalid private key")
	}
	err := privateKey.Validate()
	if err != nil {
		panic(fmt.Sprintf("signer/rsa: invalid private key: '%v'", err.Error()))
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
	}
}

func NewRS256Verifier(id string, publicKey *rsa.PublicKey) Verifier {
	return newRSAVerifier(false, id, "RS256", crypto.SHA256, publicKey)
}
func NewRS256Signer(id string, privateKey *rsa.PrivateKey) Signer {
	return newRSASigner(false, id, "RS256", crypto.SHA256, privateKey)
}

func NewRS384Verifier(id string, publicKey *rsa.PublicKey) Verifier {
	return newRSAVerifier(false, id, "RS384", crypto.SHA384, publicKey)
}
func NewRS384Signer(id string, privateKey *rsa.PrivateKey) Signer {
	return newRSASigner(false, id, "RS384", crypto.SHA384, privateKey)
}

func NewRS512Verifier(id string, publicKey *rsa.PublicKey) Verifier {
	return newRSAVerifier(false, id, "RS512", crypto.SHA512, publicKey)
}
func NewRS512Signer(id string, privateKey *rsa.PrivateKey) Signer {
	return newRSASigner(false, id, "RS512", crypto.SHA512, privateKey)
}

func NewPS256Verifier(id string, publicKey *rsa.PublicKey) Verifier {
	return newRSAVerifier(true, id, "PS256", crypto.SHA256, publicKey)
}
func NewPS256Signer(id string, privateKey *rsa.PrivateKey) Signer {
	return newRSASigner(true, id, "PS256", crypto.SHA256, privateKey)
}

func NewPS384Verifier(id string, publicKey *rsa.PublicKey) Verifier {
	return newRSAVerifier(true, id, "PS384", crypto.SHA384, publicKey)
}
func NewPS384Signer(id string, privateKey *rsa.PrivateKey) Signer {
	return newRSASigner(true, id, "PS384", crypto.SHA384, privateKey)
}

func NewPS512Verifier(id string, publicKey *rsa.PublicKey) Verifier {
	return newRSAVerifier(true, id, "PS512", crypto.SHA512, publicKey)
}
func NewPS512Signer(id string, privateKey *rsa.PrivateKey) Signer {
	return newRSASigner(true, id, "PS512", crypto.SHA512, privateKey)
}

func NewRSAVerifier(id string, name string, publicKey *rsa.PublicKey) Verifier {
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
	panic(fmt.Sprintf("signer/rsa: invalid rsa verifier name '%v'", name))
}

func NewRSASigner(id string, name string, privateKey *rsa.PrivateKey) Signer {
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
	panic(fmt.Sprintf("signer/rsa: invalid rsa signer name '%v'", name))
}
