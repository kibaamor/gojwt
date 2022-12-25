//go:build test || unit

package gojwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToken_Issuer(t *testing.T) {
	tok := NewBasicToken()

	want := "k"
	tok.WithIssuer(want)
	got := tok.Issuer()
	assert.Equal(t, want, got)
}

func TestToken_Subject(t *testing.T) {
	tok := NewBasicToken()

	want := "k"
	tok.WithSubject(want)
	got := tok.Subject()
	assert.Equal(t, want, got)
}

func TestToken_Audience(t *testing.T) {
	tok := NewBasicToken()

	want := []string{"a"}
	tok.AddAudience("a")
	got := tok.Audience()
	assert.Equal(t, want, got)

	want = []string{"a", "b"}
	tok.AddAudience("b")
	got = tok.Audience()
	assert.Equal(t, want, got)
}

func TestToken_ExpiresAt(t *testing.T) {
	tok := NewBasicToken()

	want := time.Now()
	tok.WithExpiresAt(want)
	got := tok.ExpiresAt()
	assert.Equal(t, want.Unix(), got.Unix())
}

func TestToken_NotBefore(t *testing.T) {
	tok := NewBasicToken()

	want := time.Now()
	tok.WithNotBefore(want)
	got := tok.NotBefore()
	assert.Equal(t, want.Unix(), got.Unix())
}

func TestToken_IssuedAt(t *testing.T) {
	tok := NewBasicToken()

	want := time.Now()
	tok.WithIssuedAt(want)
	got := tok.IssuedAt()
	assert.Equal(t, want.Unix(), got.Unix())
}

func TestToken_JwtID(t *testing.T) {
	tok := NewBasicToken()

	want := "k"
	tok.WithJwtID(want)
	got := tok.JwtID()
	assert.Equal(t, want, got)
}
