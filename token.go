package gojwt

import (
	"encoding/json"
	"time"
)

// https://www.rfc-editor.org/rfc/rfc7519.html#page-18
const (
	AlgorithmAbbr  = "alg"
	EncryptionAbbr = "enc"
	TypeAbbr       = "typ"
	SignerIdAbbr   = "sid"
	CipherIdAbbr   = "cid"
	IVAbbr         = "iv"

	NoneAlgNameAbbr = "none"
	JWTNameAbbr     = "JWT"
	JWENameAbbr     = "JWE"

	IssuerAbbr    = "iss"
	SubjectAbbr   = "sub"
	AudienceAbbr  = "aud"
	ExpiresAtAbbr = "exp"
	NotBeforeAbbr = "nbf"
	IssuedAtAbbr  = "iat"
	JwtIdAbbr     = "jti"
)

type Token struct {
	Headers Claims
	Bodies  Claims
}

func NewToken() *Token {
	return &Token{
		Headers: NewClaims(),
		Bodies:  NewClaims(),
	}
}

func (t *Token) String() string {
	js, _ := json.Marshal(t)
	return string(js)
}

func (t *Token) WithIssuer(issuer string) *Token {
	t.Bodies.SetString(IssuerAbbr, issuer)
	return t
}

func (t *Token) Issuer() (string, error) {
	return t.Bodies.GetString(IssuerAbbr)
}

func (t *Token) WithSubject(subject string) *Token {
	t.Bodies.SetString(SubjectAbbr, subject)
	return t
}

func (t *Token) Subject() (string, error) {
	return t.Bodies.GetString(SubjectAbbr)
}

func (t *Token) AddAudience(audience string) *Token {
	audiences, _ := t.Bodies.GetStringArray(AudienceAbbr)
	t.Bodies.SetStringArray(AudienceAbbr, append(audiences, audience))
	return t
}

func (t *Token) Audience() ([]string, error) {
	return t.Bodies.GetStringArray(AudienceAbbr)
}

func (t *Token) WithExpiresAt(expiresAt time.Time) *Token {
	t.Bodies.SetTime(ExpiresAtAbbr, expiresAt)
	return t
}

func (t *Token) ExpiresAt() (time.Time, error) {
	return t.Bodies.GetTime(ExpiresAtAbbr)
}

func (t *Token) WithNotBefore(notBefore time.Time) *Token {
	t.Bodies.SetTime(NotBeforeAbbr, notBefore)
	return t
}

func (t *Token) NotBefore() (time.Time, error) {
	return t.Bodies.GetTime(NotBeforeAbbr)
}

func (t *Token) WithIssuedAt(issuedAt time.Time) *Token {
	t.Bodies.SetTime(IssuedAtAbbr, issuedAt)
	return t
}

func (t *Token) IssuedAt() (time.Time, error) {
	return t.Bodies.GetTime(IssuedAtAbbr)
}

func (t *Token) WithJwtId(jti string) *Token {
	t.Bodies.SetString(JwtIdAbbr, jti)
	return t
}

func (t *Token) JwtId() (string, error) {
	return t.Bodies.GetString(JwtIdAbbr)
}

func (t *Token) setHeaderString(key, value string) *Token {
	t.Headers[key] = value
	return t
}

func (t *Token) setAlgorithm(name string) *Token {
	return t.setHeaderString(AlgorithmAbbr, name)
}

func (t *Token) setSignerId(sid string) *Token {
	return t.setHeaderString(SignerIdAbbr, sid)
}

func (t *Token) setAlgorithmNone() *Token {
	return t.setAlgorithm(NoneAlgNameAbbr)
}

func (t *Token) setTypeJWT() *Token {
	return t.setHeaderString(TypeAbbr, JWTNameAbbr)
}

func (t *Token) setTypeJWE() *Token {
	return t.setHeaderString(TypeAbbr, JWENameAbbr)
}

func (t *Token) setEncryption(name string) *Token {
	return t.setHeaderString(EncryptionAbbr, name)
}

func (t *Token) setCipherId(cid string) *Token {
	return t.setHeaderString(CipherIdAbbr, cid)
}

func (t *Token) setIV(iv string) *Token {
	return t.setHeaderString(IVAbbr, iv)
}
