package signer

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
)

var errHMACVerification = errors.New("signer/hmac: verification error")

type hmacSigner struct {
	id   string
	name string
	hash crypto.Hash
	key  []byte
}

func (s *hmacSigner) Id() string {
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
	h.Write(data)
	return h.Sum(nil), nil
}

func (s *hmacSigner) Verifier() Verifier {
	return s
}

func newHSSigner(id, name string, hash crypto.Hash, key []byte) Signer {
	if !hash.Available() {
		panic(fmt.Sprintf("signer/hmac: invalid hash '%v'", hash))
	}
	if key == nil {
		panic("signer/hmac: invalid key")
	}
	return &hmacSigner{
		id:   id,
		name: name,
		hash: hash,
		key:  key,
	}
}

func NewHS256Signer(id string, key []byte) Signer {
	return newHSSigner(id, "HS256", crypto.SHA256, key)
}
func NewHS384Signer(id string, key []byte) Signer {
	return newHSSigner(id, "HS384", crypto.SHA384, key)
}
func NewHS512Signer(id string, key []byte) Signer {
	return newHSSigner(id, "HS512", crypto.SHA512, key)
}

func NewHMACSigner(id, name string, key []byte) Signer {
	if name == "HS256" {
		return NewHS256Signer(id, key)
	} else if name == "HS384" {
		return NewHS384Signer(id, key)
	} else if name == "HS512" {
		return NewHS512Signer(id, key)
	}
	panic(fmt.Sprintf("signer/hmac: invalid hmac verifier name '%v'", name))
}
