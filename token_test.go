//go:build test || unit

package gojwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestToken_Issuer(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := "k"
	tok.WithIssuer(want)
	got := tok.Issuer()
	require.Equal(want, got)
}

func TestToken_Subject(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := "k"
	tok.WithSubject(want)
	got := tok.Subject()
	require.Equal(want, got)
}

func TestToken_Audience(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := []string{"a"}
	tok.AddAudience("a")
	got := tok.Audience()
	require.Equal(want, got)

	want = []string{"a", "b"}
	tok.AddAudience("b")
	got = tok.Audience()
	require.Equal(want, got)
}

func TestToken_ExpiresAt(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := time.Now()
	tok.WithExpiresAt(want)
	got := tok.ExpiresAt()
	require.Equal(want.Unix(), got.Unix())
}

func TestToken_NotBefore(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := time.Now()
	tok.WithNotBefore(want)
	got := tok.NotBefore()
	require.Equal(want.Unix(), got.Unix())
}

func TestToken_IssuedAt(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := time.Now()
	tok.WithIssuedAt(want)
	got := tok.IssuedAt()
	require.Equal(want.Unix(), got.Unix())
}

func TestToken_JwtID(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tok := NewBasicToken()

	want := "k"
	tok.WithJwtID(want)
	got := tok.JwtID()
	require.Equal(want, got)
}
