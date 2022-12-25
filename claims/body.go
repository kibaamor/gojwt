package claims

import (
	"time"

	"github.com/kibaamor/gojwt/utils"
)

type BodyInterface interface {
	GetJwtID() string
	SetJwtID(string)
	GetIssuer() string
	SetIssuer(string)
	GetSubject() string
	SetSubject(string)
	GetAudience() []string
	AddAudience(string)
	GetExpiresAt() *time.Time
	SetExpiresAt(time.Time)
	GetNotBefore() *time.Time
	SetNotBefore(time.Time)
	GetIssuedAt() *time.Time
	SetIssuedAt(time.Time)

	Valid() error
}

type BasicBody struct {
	JwtID     string   `json:"jti,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Audience  []string `json:"audience,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
}

func (b *BasicBody) GetJwtID() string {
	return b.JwtID
}

func (b *BasicBody) SetJwtID(s string) {
	b.JwtID = s
}

func (b *BasicBody) GetIssuer() string {
	return b.Issuer
}

func (b *BasicBody) SetIssuer(s string) {
	b.Issuer = s
}

func (b *BasicBody) GetSubject() string {
	return b.Subject
}

func (b *BasicBody) SetSubject(s string) {
	b.Subject = s
}

func (b *BasicBody) GetAudience() []string {
	return b.Audience
}

func (b *BasicBody) AddAudience(s string) {
	if !utils.Contains(b.Audience, s) {
		b.Audience = append(b.Audience, s)
	}
}

func (b *BasicBody) GetExpiresAt() *time.Time {
	if b.ExpiresAt == 0 {
		return nil
	}
	t := time.Unix(b.ExpiresAt, 0)
	return &t
}

func (b *BasicBody) SetExpiresAt(t time.Time) {
	b.ExpiresAt = t.Unix()
}

func (b *BasicBody) GetNotBefore() *time.Time {
	if b.NotBefore == 0 {
		return nil
	}
	t := time.Unix(b.NotBefore, 0)
	return &t
}

func (b *BasicBody) SetNotBefore(t time.Time) {
	b.NotBefore = t.Unix()
}

func (b *BasicBody) GetIssuedAt() *time.Time {
	if b.IssuedAt == 0 {
		return nil
	}
	t := time.Unix(b.IssuedAt, 0)
	return &t
}

func (b *BasicBody) SetIssuedAt(t time.Time) {
	b.IssuedAt = t.Unix()
}

func (*BasicBody) Valid() error {
	return nil
}
