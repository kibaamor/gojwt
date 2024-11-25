//go:build test || unit

package gojwt

import (
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func assertChecker(t *testing.T, b *Builder, name, want string) {
	require := require.New(t)

	jwt, err := b.Sign()
	require.NoError(err)

	c := NewBasicChecker()
	c.SetTimeFunc(timeFuncForTest)
	if b.Signer != nil {
		c.AllowVerifier(b.Signer.Verifier())
	}
	if b.Cipher != nil {
		c.AllowCipher(b.Cipher)
	}
	if name != "" {
		c.
			AllowIssuers(name).
			AllowSubjects(name).
			AllowAudiences(name + name).
			AllowJwtIDs(name)
	}

	got, err := c.Check(jwt)
	require.NoError(err)
	require.Equal(want, got.String())
}

func TestChecker_Empty(t *testing.T) {
	t.Parallel()

	b := NewBasicBuilder()
	want := `{"Header":{"alg":"none","typ":"JWT"},"Body":{}}`
	assertChecker(t, b, "", want)
}

func TestChecker_FullReservedClaims(t *testing.T) {
	t.Parallel()

	b := createBuilderForTest("test")
	want := `{"Header":{"alg":"none","typ":"JWT"},"Body":{"jti":"test","issuer":"test","subject":"test","audience":["test","testtest"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`
	assertChecker(t, b, "test", want)
}

func TestChecker_HMAC(t *testing.T) {
	tests := []struct {
		id   string
		name string
		want string
	}{
		{
			id:   "hs256",
			name: "HS256",
			want: `{"Header":{"alg":"HS256","typ":"JWT","sid":"hs256"},"Body":{"jti":"HS256","issuer":"HS256","subject":"HS256","audience":["HS256","HS256HS256"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "hs384",
			name: "HS384",
			want: `{"Header":{"alg":"HS384","typ":"JWT","sid":"hs384"},"Body":{"jti":"HS384","issuer":"HS384","subject":"HS384","audience":["HS384","HS384HS384"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "hs512",
			name: "HS512",
			want: `{"Header":{"alg":"HS512","typ":"JWT","sid":"hs512"},"Body":{"jti":"HS512","issuer":"HS512","subject":"HS512","audience":["HS512","HS512HS512"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			s, err := NewHMACSigner(tt.id, tt.name, []byte(tt.name))
			require.NoError(err)
			b := createBuilderForTest(tt.name).WithSigner(s)
			assertChecker(t, b, tt.name, tt.want)
		})
	}
}

func TestChecker_RSA(t *testing.T) {
	tests := []struct {
		id   string
		name string
		want string
	}{
		{
			id:   "rs256",
			name: "RS256",
			want: `{"Header":{"alg":"RS256","typ":"JWT","sid":"rs256"},"Body":{"jti":"RS256","issuer":"RS256","subject":"RS256","audience":["RS256","RS256RS256"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "rs384",
			name: "RS384",
			want: `{"Header":{"alg":"RS384","typ":"JWT","sid":"rs384"},"Body":{"jti":"RS384","issuer":"RS384","subject":"RS384","audience":["RS384","RS384RS384"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "rs512",
			name: "RS512",
			want: `{"Header":{"alg":"RS512","typ":"JWT","sid":"rs512"},"Body":{"jti":"RS512","issuer":"RS512","subject":"RS512","audience":["RS512","RS512RS512"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "ps256",
			name: "PS256",
			want: `{"Header":{"alg":"PS256","typ":"JWT","sid":"ps256"},"Body":{"jti":"PS256","issuer":"PS256","subject":"PS256","audience":["PS256","PS256PS256"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "ps384",
			name: "PS384",
			want: `{"Header":{"alg":"PS384","typ":"JWT","sid":"ps384"},"Body":{"jti":"PS384","issuer":"PS384","subject":"PS384","audience":["PS384","PS384PS384"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "ps512",
			name: "PS512",
			want: `{"Header":{"alg":"PS512","typ":"JWT","sid":"ps512"},"Body":{"jti":"PS512","issuer":"PS512","subject":"PS512","audience":["PS512","PS512PS512"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			s, err := NewRSASigner(tt.id, tt.name, rsaPrivateKeyForTest)
			require.NoError(err)
			b := createBuilderForTest(tt.name).WithSigner(s)
			assertChecker(t, b, tt.name, tt.want)
		})
	}
}

func TestChecker_ECDSA(t *testing.T) {
	tests := []struct {
		id         string
		name       string
		privateKey *ecdsa.PrivateKey
		want       string
	}{
		{
			id:         "es256",
			name:       "ES256",
			privateKey: ecdsaP256PrivateKeyForTest,
			want:       `{"Header":{"alg":"ES256","typ":"JWT","sid":"es256"},"Body":{"jti":"ES256","issuer":"ES256","subject":"ES256","audience":["ES256","ES256ES256"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:         "es384",
			name:       "ES384",
			privateKey: ecdsaP384PrivateKeyForTest,
			want:       `{"Header":{"alg":"ES384","typ":"JWT","sid":"es384"},"Body":{"jti":"ES384","issuer":"ES384","subject":"ES384","audience":["ES384","ES384ES384"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:         "es512",
			name:       "ES512",
			privateKey: ecdsaP521PrivateKeyForTest,
			want:       `{"Header":{"alg":"ES512","typ":"JWT","sid":"es512"},"Body":{"jti":"ES512","issuer":"ES512","subject":"ES512","audience":["ES512","ES512ES512"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			s, err := NewECDSASigner(tt.id, tt.name, tt.privateKey)
			require.NoError(err)
			b := createBuilderForTest(tt.name).WithSigner(s)
			assertChecker(t, b, tt.name, tt.want)
		})
	}
}

func TestChecker_AESCBC(t *testing.T) {
	tests := []struct {
		id   string
		name string
		key  string
		want string
	}{
		{
			id:   "a128cbc",
			name: "A128CBC",
			key:  "kibazencnA128CBC",
			want: `{"Header":{"alg":"none","enc":"A128CBC","typ":"JWE","cid":"a128cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"A128CBC","issuer":"A128CBC","subject":"A128CBC","audience":["A128CBC","A128CBCA128CBC"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "a192cbc",
			name: "A192CBC",
			key:  "kibazencnA192CBCnA192CBC",
			want: `{"Header":{"alg":"none","enc":"A192CBC","typ":"JWE","cid":"a192cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"A192CBC","issuer":"A192CBC","subject":"A192CBC","audience":["A192CBC","A192CBCA192CBC"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:   "a256cbc",
			name: "A256CBC",
			key:  "kibazencnA256CBCkibazencnA256CBC",
			want: `{"Header":{"alg":"none","enc":"A256CBC","typ":"JWE","cid":"a256cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"A256CBC","issuer":"A256CBC","subject":"A256CBC","audience":["A256CBC","A256CBCA256CBC"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			c, err := NewAESCBCCipher(tt.id, []byte(tt.key))
			require.NoError(err)
			b := createBuilderForTest(tt.name).WithCipher(c).WithIVGenerator(ivGeneratorForTest(iv))
			assertChecker(t, b, tt.name, tt.want)
		})
	}
}

func TestChecker_HMAC_AESCBC(t *testing.T) {
	tests := []struct {
		id        string
		hmacName  string
		aesCbcKey string
		want      string
	}{
		{
			id:        "hs256_a128cbc",
			hmacName:  "HS256",
			aesCbcKey: "kibazencnA128CBC",
			want:      `{"Header":{"alg":"HS256","enc":"A128CBC","typ":"JWE","sid":"hs256_a128cbc","cid":"hs256_a128cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs256_a128cbc","issuer":"hs256_a128cbc","subject":"hs256_a128cbc","audience":["hs256_a128cbc","hs256_a128cbchs256_a128cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs256_a192cbc",
			hmacName:  "HS256",
			aesCbcKey: "kibazencnA192CBCnA192CBC",
			want:      `{"Header":{"alg":"HS256","enc":"A192CBC","typ":"JWE","sid":"hs256_a192cbc","cid":"hs256_a192cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs256_a192cbc","issuer":"hs256_a192cbc","subject":"hs256_a192cbc","audience":["hs256_a192cbc","hs256_a192cbchs256_a192cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs256_a256cbc",
			hmacName:  "HS256",
			aesCbcKey: "kibazencnA256CBCkibazencnA256CBC",
			want:      `{"Header":{"alg":"HS256","enc":"A256CBC","typ":"JWE","sid":"hs256_a256cbc","cid":"hs256_a256cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs256_a256cbc","issuer":"hs256_a256cbc","subject":"hs256_a256cbc","audience":["hs256_a256cbc","hs256_a256cbchs256_a256cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs384_a128cbc",
			hmacName:  "HS384",
			aesCbcKey: "kibazencnA128CBC",
			want:      `{"Header":{"alg":"HS384","enc":"A128CBC","typ":"JWE","sid":"hs384_a128cbc","cid":"hs384_a128cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs384_a128cbc","issuer":"hs384_a128cbc","subject":"hs384_a128cbc","audience":["hs384_a128cbc","hs384_a128cbchs384_a128cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs384_a192cbc",
			hmacName:  "HS384",
			aesCbcKey: "kibazencnA192CBCnA192CBC",
			want:      `{"Header":{"alg":"HS384","enc":"A192CBC","typ":"JWE","sid":"hs384_a192cbc","cid":"hs384_a192cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs384_a192cbc","issuer":"hs384_a192cbc","subject":"hs384_a192cbc","audience":["hs384_a192cbc","hs384_a192cbchs384_a192cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs384_a256cbc",
			hmacName:  "HS384",
			aesCbcKey: "kibazencnA256CBCkibazencnA256CBC",
			want:      `{"Header":{"alg":"HS384","enc":"A256CBC","typ":"JWE","sid":"hs384_a256cbc","cid":"hs384_a256cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs384_a256cbc","issuer":"hs384_a256cbc","subject":"hs384_a256cbc","audience":["hs384_a256cbc","hs384_a256cbchs384_a256cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs512_a128cbc",
			hmacName:  "HS512",
			aesCbcKey: "kibazencnA128CBC",
			want:      `{"Header":{"alg":"HS512","enc":"A128CBC","typ":"JWE","sid":"hs512_a128cbc","cid":"hs512_a128cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs512_a128cbc","issuer":"hs512_a128cbc","subject":"hs512_a128cbc","audience":["hs512_a128cbc","hs512_a128cbchs512_a128cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs512_a192cbc",
			hmacName:  "HS512",
			aesCbcKey: "kibazencnA192CBCnA192CBC",
			want:      `{"Header":{"alg":"HS512","enc":"A192CBC","typ":"JWE","sid":"hs512_a192cbc","cid":"hs512_a192cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs512_a192cbc","issuer":"hs512_a192cbc","subject":"hs512_a192cbc","audience":["hs512_a192cbc","hs512_a192cbchs512_a192cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
		{
			id:        "hs512_a256cbc",
			hmacName:  "HS512",
			aesCbcKey: "kibazencnA256CBCkibazencnA256CBC",
			want:      `{"Header":{"alg":"HS512","enc":"A256CBC","typ":"JWE","sid":"hs512_a256cbc","cid":"hs512_a256cbc","iv":"NGtpYmF6ZW40a2liYXplbg"},"Body":{"jti":"hs512_a256cbc","issuer":"hs512_a256cbc","subject":"hs512_a256cbc","audience":["hs512_a256cbc","hs512_a256cbchs512_a256cbc"],"exp":1136217845,"nbf":1136214245,"iat":1136214245}}`,
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			s, err := NewHMACSigner(tt.id, tt.hmacName, []byte(tt.hmacName))
			require.NoError(err)
			c, err := NewAESCBCCipher(tt.id, []byte(tt.aesCbcKey))
			require.NoError(err)
			b := createBuilderForTest(tt.id).WithSigner(s).WithCipher(c).WithIVGenerator(ivGeneratorForTest(iv))
			assertChecker(t, b, tt.id, tt.want)
		})
	}
}
