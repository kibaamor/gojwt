package gojwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/kibaamor/gojwt/cipher"
	"github.com/kibaamor/gojwt/signer"
	"github.com/kibaamor/gojwt/util"
)

var (
	errJWT            = errors.New("checker: invalid jwt string")
	errSignerId       = errors.New("checker: invalid signer id")
	errCipherId       = errors.New("checker: invalid cipher id")
	errCipherMismatch = errors.New("checker: cipher name mismatch")
)

type Checker struct {
	Verifiers map[string]signer.Verifier
	Ciphers   map[string]cipher.Cipher
}

func NewChecker() *Checker {
	return &Checker{
		Verifiers: make(map[string]signer.Verifier),
		Ciphers:   make(map[string]cipher.Cipher),
	}
}

func (c *Checker) AllowVerifier(ve signer.Verifier) *Checker {
	c.Verifiers[ve.Id()] = ve
	return c
}

func (c *Checker) AllowCipher(ci cipher.Cipher) *Checker {
	c.Ciphers[ci.Id()] = ci
	return c
}

func (c *Checker) Check(jwt string) (*Token, error) {
	jwtBytes := []byte(jwt)
	segments := bytes.SplitN(jwtBytes, []byte{'.'}, 3)
	if len(segments) != 3 {
		return nil, errJWT
	}

	headers, err := c.unmarshalHeaders(segments[0])
	if err != nil {
		return nil, err
	}

	dataLen := len(segments[0]) + 1 + len(segments[1])
	if err = c.checkAlgorithm(headers, jwtBytes[:dataLen], jwtBytes[dataLen+1:]); err != nil {
		return nil, err
	}

	bodiesBytes, err := util.RawURLDecode(segments[1])
	if err != nil {
		return nil, err
	}
	bodiesBytes, err = c.checkEncryptionAndDecrypt(headers, bodiesBytes)
	if err != nil {
		return nil, err
	}

	bodies := NewClaims()
	if err = json.Unmarshal(bodiesBytes, &bodies); err != nil {
		return nil, err
	}

	return &Token{
		Headers: headers,
		Bodies:  bodies,
	}, nil
}

func (c *Checker) unmarshalHeaders(data []byte) (Claims, error) {
	data, err := util.RawURLDecode(data)
	if err != nil {
		return nil, err
	}

	headers := NewClaims()
	if err = json.Unmarshal(data, &headers); err != nil {
		return nil, err
	}

	return headers, nil
}

func (c *Checker) checkAlgorithm(headers Claims, data, signature []byte) error {
	alg, err := headers.GetString(AlgorithmAbbr)
	if err != nil {
		return err
	}

	if alg == NoneAlgNameAbbr {
		return nil
	}

	sid, err := headers.GetString(SignerIdAbbr)
	if err != nil {
		return err
	}

	ve, ok := c.Verifiers[sid]
	if !ok {
		return errSignerId
	}

	if signature, err = util.RawURLDecode(signature); err != nil {
		return err
	}

	return ve.Verify(data, signature)
}

func (c *Checker) checkEncryptionAndDecrypt(headers Claims, bodiesBytes []byte) ([]byte, error) {
	typ, err := headers.GetString(TypeAbbr)
	if err != nil {
		return nil, err
	}

	if typ == JWTNameAbbr {
		return bodiesBytes, nil
	}

	cid, err := headers.GetString(CipherIdAbbr)
	if err != nil {
		return nil, err
	}

	ci, ok := c.Ciphers[cid]
	if !ok {
		return nil, errCipherId
	}

	enc, err := headers.GetString(EncryptionAbbr)
	if err != nil {
		return nil, err
	}

	if ci.Name() != enc {
		return nil, errCipherMismatch
	}

	ivBase64, err := headers.GetString(IVAbbr)
	if err != nil {
		return nil, err
	}
	iv, err := base64.RawURLEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, err
	}

	return ci.Decrypt(bodiesBytes, iv)
}
