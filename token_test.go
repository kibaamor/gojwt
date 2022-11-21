package gojwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestToken_Issuer(t *testing.T) {
	tok := NewToken()

	_, err := tok.Issuer()
	assert.NotNil(t, err)

	want := "k"
	tok.WithIssuer(want)
	got, err := tok.Issuer()
	if assert.Nil(t, err) {
		assert.Equal(t, want, got)
	}
}

func TestToken_Subject(t *testing.T) {
	tok := NewToken()

	_, err := tok.Subject()
	assert.NotNil(t, err)

	want := "k"
	tok.WithSubject(want)
	got, err := tok.Subject()
	if assert.Nil(t, err) {
		assert.Equal(t, want, got)
	}
}

func TestToken_Audience(t *testing.T) {
	tok := NewToken()

	_, err := tok.Audience()
	assert.NotNil(t, err)

	want := []string{"a"}
	tok.AddAudience("a")
	got, err := tok.Audience()
	if assert.Nil(t, err) {
		assert.Equal(t, want, got)
	}

	want = []string{"a", "b"}
	tok.AddAudience("b")
	got, err = tok.Audience()
	if assert.Nil(t, err) {
		assert.Equal(t, want, got)
	}
}

func TestToken_ExpiresAt(t *testing.T) {
	tok := NewToken()

	_, err := tok.ExpiresAt()
	assert.NotNil(t, err)

	want := time.Now()
	tok.WithExpiresAt(want)
	got, err := tok.ExpiresAt()
	if assert.Nil(t, err) {
		assert.Equal(t, want.Unix(), got.Unix())
	}
}

func TestToken_NotBefore(t *testing.T) {
	tok := NewToken()

	_, err := tok.NotBefore()
	assert.NotNil(t, err)

	want := time.Now()
	tok.WithNotBefore(want)
	got, err := tok.NotBefore()
	if assert.Nil(t, err) {
		assert.Equal(t, want.Unix(), got.Unix())
	}
}

func TestToken_IssuedAt(t *testing.T) {
	tok := NewToken()

	_, err := tok.IssuedAt()
	assert.NotNil(t, err)

	want := time.Now()
	tok.WithIssuedAt(want)
	got, err := tok.IssuedAt()
	if assert.Nil(t, err) {
		assert.Equal(t, want.Unix(), got.Unix())
	}
}

func TestToken_JwtId(t *testing.T) {
	tok := NewToken()

	_, err := tok.JwtId()
	assert.NotNil(t, err)

	want := "k"
	tok.WithJwtId(want)
	got, err := tok.JwtId()
	if assert.Nil(t, err) {
		assert.Equal(t, want, got)
	}
}
