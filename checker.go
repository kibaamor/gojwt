package gojwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	errJWT = errors.New("gojwt/checker: invalid jwt string")
)

type Checker struct {
	Token     Token
	Verifiers map[string]Verifier
	Ciphers   map[string]Cipher
	Issuers   []string
	Subjects  []string
	Audiences []string
	JwtIDs    []string
	TimeFunc  func() time.Time
}

func NewBasicChecker() *Checker {
	return NewCheckerWithToken(NewBasicToken())
}

func NewCheckerWithToken(token Token) *Checker {
	return &Checker{
		Token:     token,
		Verifiers: make(map[string]Verifier),
		Ciphers:   make(map[string]Cipher),
	}
}

func (c *Checker) AllowVerifier(ve Verifier) *Checker {
	if ve != nil {
		c.Verifiers[ve.ID()] = ve
	}
	return c
}

func (c *Checker) AllowCipher(ci Cipher) *Checker {
	if ci != nil {
		c.Ciphers[ci.ID()] = ci
	}
	return c
}

func (c *Checker) AllowIssuers(issuers ...string) *Checker {
	c.Issuers = append(c.Issuers, issuers...)
	return c
}

func (c *Checker) AllowSubjects(subjects ...string) *Checker {
	c.Subjects = append(c.Subjects, subjects...)
	return c
}

func (c *Checker) AllowAudiences(audiences ...string) *Checker {
	c.Audiences = append(c.Audiences, audiences...)
	return c
}

func (c *Checker) AllowJwtIDs(jwtIDs ...string) *Checker {
	c.JwtIDs = append(c.JwtIDs, jwtIDs...)
	return c
}

func (c *Checker) SetTimeFunc(timeFunc func() time.Time) *Checker {
	c.TimeFunc = timeFunc
	return c
}

func (c *Checker) Check(jwt string) (*Token, error) {
	jwtBytes := []byte(jwt)
	segments := bytes.SplitN(jwtBytes, []byte{'.'}, 3)
	if len(segments) != 3 {
		return nil, errJWT
	}

	err := c.unmarshalHeaders(segments[0])
	if err != nil {
		return nil, err
	}

	dataLen := len(segments[0]) + 1 + len(segments[1])
	if err = c.checkAlgorithm(jwtBytes[:dataLen], jwtBytes[dataLen+1:]); err != nil {
		return nil, err
	}

	bodiesBytes, err := RawURLDecode(segments[1])
	if err != nil {
		return nil, fmt.Errorf("gojwt/checker: decode body failed '%w'", err)
	}
	bodiesBytes, err = c.checkEncryptionAndDecrypt(bodiesBytes)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(bodiesBytes, &c.Token.Body); err != nil {
		return nil, fmt.Errorf("gojwt/checker: body is not a valid json '%w'", err)
	}

	return &c.Token, c.checkToken()
}

func (c *Checker) unmarshalHeaders(data []byte) error {
	data, err := RawURLDecode(data)
	if err != nil {
		return fmt.Errorf("gojwt/checker: decode header failed '%w'", err)
	}

	err = json.Unmarshal(data, &c.Token.Header)
	if err != nil {
		return fmt.Errorf("gojwt/checker: header is not a valid json '%w'", err)
	}

	return nil
}

func (c *Checker) newSignerIDError(sid string) error {
	b := strings.Builder{}
	first := true
	for id := range c.Verifiers {
		if first {
			first = false
		} else {
			_ = b.WriteByte(',')
		}
		_, _ = b.WriteString(id)
	}

	return fmt.Errorf("gojwt/checker: invalid signer id. got: '%s', want: '%s'", sid, b.String())
}

func (c *Checker) checkAlgorithm(data, signature []byte) error {
	alg := c.Token.Header.GetAlgorithm()
	if alg == NoneAlgNameAbbr {
		return nil
	}

	sid := c.Token.Header.GetSignerID()
	ve, ok := c.Verifiers[sid]
	if !ok {
		return c.newSignerIDError(sid)
	}

	var err error
	if signature, err = RawURLDecode(signature); err != nil {
		return fmt.Errorf("gojwt/checker: decode signature failed '%w'", err)
	}

	return ve.Verify(data, signature)
}

func (c *Checker) newCipherIDError(cid string) error {
	b := strings.Builder{}
	first := true
	for id := range c.Ciphers {
		if first {
			first = false
		} else {
			_ = b.WriteByte(',')
		}
		_, _ = b.WriteString(id)
	}

	return fmt.Errorf("gojwt/checker: invalid cipher id. got: '%s', want: '%s'", cid, b.String())
}

func (c *Checker) checkEncryptionAndDecrypt(bodiesBytes []byte) ([]byte, error) {
	typ := c.Token.Header.GetType()
	if typ == JWTNameAbbr {
		return bodiesBytes, nil
	}

	cid := c.Token.Header.GetCipherID()
	ci, ok := c.Ciphers[cid]
	if !ok {
		return nil, c.newCipherIDError(cid)
	}

	enc := c.Token.Header.GetEncryption()
	if ci.Name() != enc {
		return nil, fmt.Errorf("gojwt/checker: invalid cipher name. got: '%s', want(%s): '%s'",
			enc, ci.ID(), ci.Name())
	}

	ivBase64 := c.Token.Header.GetIV()
	iv, err := base64.RawURLEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, fmt.Errorf("gojwt/checker: decode iv failed '%w'", err)
	}

	return ci.Decrypt(bodiesBytes, iv)
}

func (c *Checker) checkToken() error {
	if err := c.Token.Body.Valid(); err != nil {
		return err
	}

	if err := c.checkTokenTime(); err != nil {
		return err
	}

	if len(c.Issuers) > 0 {
		issuer := c.Token.Body.GetIssuer()
		if len(issuer) == 0 || !Contains(c.Issuers, issuer) {
			return fmt.Errorf("gojwt/checker: invalid issuer. got: '%s', want: '%s'",
				issuer, strings.Join(c.Issuers, ","))
		}
	}

	if len(c.Subjects) > 0 {
		subject := c.Token.Body.GetSubject()
		if len(subject) == 0 || !Contains(c.Subjects, subject) {
			return fmt.Errorf("gojwt/checker: invalid subject. got: '%s', want: '%s'",
				subject, strings.Join(c.Subjects, ","))
		}
	}

	if len(c.JwtIDs) > 0 {
		jwtID := c.Token.Body.GetJwtID()
		if len(jwtID) == 0 || !Contains(c.JwtIDs, jwtID) {
			return fmt.Errorf("gojwt/checker: invalid jwt id. got: '%s', want: '%s'",
				jwtID, strings.Join(c.JwtIDs, ","))
		}
	}

	return c.checkTokenAudience()
}

func (c *Checker) checkTokenTime() error {
	timeFunc := c.TimeFunc
	if timeFunc == nil {
		timeFunc = time.Now
	}

	now := timeFunc()
	if expiresAt := c.Token.Body.GetExpiresAt(); expiresAt != nil && now.After(*expiresAt) {
		return fmt.Errorf("gojwt/checker: invalid token(after ExpiresAt). now: '%s', expiresAt: '%s'",
			now.String(), expiresAt.String())
	}
	if notBefore := c.Token.Body.GetNotBefore(); notBefore != nil && now.Before(*notBefore) {
		return fmt.Errorf("gojwt/checker: invalid token(before NotBefore). now: '%s', notBefore: '%s'",
			now.String(), notBefore.String())
	}
	return nil
}

func (c *Checker) checkTokenAudience() error {
	if len(c.Audiences) == 0 {
		return nil
	}

	audiences := c.Token.Body.GetAudience()
	if len(audiences) == 0 {
		return fmt.Errorf("gojwt/checker: invalid audience(s). got: '', want: '%s'",
			strings.Join(c.Audiences, ","))
	}

	contains := false
	for _, audience := range audiences {
		contains = Contains(c.Audiences, audience)
		if contains {
			break
		}
	}
	if !contains {
		return fmt.Errorf("gojwt/checker: invalid audience(s). got: '%s', want: '%s'",
			strings.Join(audiences, ","), strings.Join(c.Audiences, ","))
	}

	return nil
}
