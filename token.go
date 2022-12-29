package gojwt

import (
	"encoding/json"
	"time"
)

type Token struct {
	Header HeaderInterface
	Body   BodyInterface
}

func NewBasicToken() Token {
	return Token{
		Header: &BasicHeader{},
		Body:   &BasicBody{},
	}
}

func (t Token) String() string {
	js, _ := json.Marshal(t)
	return string(js)
}

func (t Token) WithIssuer(issuer string) Token {
	t.Body.SetIssuer(issuer)
	return t
}

func (t Token) Issuer() string {
	return t.Body.GetIssuer()
}

func (t Token) WithSubject(subject string) Token {
	t.Body.SetSubject(subject)
	return t
}

func (t Token) Subject() string {
	return t.Body.GetSubject()
}

func (t Token) AddAudience(audience string) Token {
	t.Body.AddAudience(audience)
	return t
}

func (t Token) Audience() []string {
	return t.Body.GetAudience()
}

func (t Token) WithExpiresAt(expiresAt time.Time) Token {
	t.Body.SetExpiresAt(expiresAt)
	return t
}

func (t Token) ExpiresAt() *time.Time {
	return t.Body.GetExpiresAt()
}

func (t Token) WithNotBefore(notBefore time.Time) Token {
	t.Body.SetNotBefore(notBefore)
	return t
}

func (t Token) NotBefore() *time.Time {
	return t.Body.GetNotBefore()
}

func (t Token) WithIssuedAt(issuedAt time.Time) Token {
	t.Body.SetIssuedAt(issuedAt)
	return t
}

func (t Token) IssuedAt() *time.Time {
	return t.Body.GetIssuedAt()
}

func (t Token) WithJwtID(jti string) Token {
	t.Body.SetJwtID(jti)
	return t
}

func (t Token) JwtID() string {
	return t.Body.GetJwtID()
}
