package gojwt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256" // init
	_ "crypto/sha512" // init
	"errors"
	"fmt"
)

var (
	errHMACVerification = errors.New("gojwt/hmac: verification error")
	errHMACKey          = errors.New("gojwt/hmac: invalid key")
)

type hmacSigner struct {
	id   string
	name string
	hash crypto.Hash
	key  []byte
}

func (s *hmacSigner) ID() string {
	return s.id
}

func (s *hmacSigner) Name() string {
	return s.name
}

func (s *hmacSigner) Verify(data, signature []byte) error {
	sig, err := s.Sign(data)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, signature) {
		return errHMACVerification
	}
	return nil
}

func (s *hmacSigner) Sign(data []byte) ([]byte, error) {
	h := hmac.New(s.hash.New, s.key)
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), err
}

func (s *hmacSigner) Verifier() Verifier {
	return s
}

func newHSSigner(id, name string, hash crypto.Hash, key []byte) (*hmacSigner, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("gojwt/hmac: invalid hash '%v'", hash)
	}
	if key == nil {
		return nil, errHMACKey
	}
	return &hmacSigner{
		id:   id,
		name: name,
		hash: hash,
		key:  key,
	}, nil
}

func NewHS256Signer(id string, key []byte) (Signer, error) {
	return newHSSigner(id, "HS256", crypto.SHA256, key)
}
func NewHS256Verifier(id string, key []byte) (Verifier, error) {
	return newHSSigner(id, "HS256", crypto.SHA256, key)
}

func NewHS384Signer(id string, key []byte) (Signer, error) {
	return newHSSigner(id, "HS384", crypto.SHA384, key)
}
func NewHS384Verifier(id string, key []byte) (Verifier, error) {
	return newHSSigner(id, "HS384", crypto.SHA384, key)
}

func NewHS512Signer(id string, key []byte) (Signer, error) {
	return newHSSigner(id, "HS512", crypto.SHA512, key)
}
func NewHS512Verifier(id string, key []byte) (Verifier, error) {
	return newHSSigner(id, "HS512", crypto.SHA512, key)
}

func NewHMACSigner(id, name string, key []byte) (Signer, error) {
	if name == "HS256" {
		return NewHS256Signer(id, key)
	} else if name == "HS384" {
		return NewHS384Signer(id, key)
	} else if name == "HS512" {
		return NewHS512Signer(id, key)
	}
	return nil, fmt.Errorf("gojwt/hmac: invalid hmac signer name '%v'", name)
}

func NewHMACVerifier(id, name string, key []byte) (Verifier, error) {
	if name == "HS256" {
		return NewHS256Verifier(id, key)
	} else if name == "HS384" {
		return NewHS384Verifier(id, key)
	} else if name == "HS512" {
		return NewHS512Verifier(id, key)
	}
	return nil, fmt.Errorf("gojwt/hmac: invalid hmac verifier name '%v'", name)
}
