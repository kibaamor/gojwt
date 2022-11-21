package gojwt

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/kibaamor/gojwt/cipher"
	"github.com/kibaamor/gojwt/internal/test"
	"github.com/kibaamor/gojwt/signer"
	"github.com/stretchr/testify/assert"
	"testing"
)

func assertCheckerWithIV(t *testing.T, b *Builder, want string, iv []byte) {
	jwt, err := b.SignWithIV(iv)
	assert.Nil(t, err)

	c := NewChecker()
	if b.Signer != nil {
		c.AllowVerifier(b.Signer.Verifier())
	}
	if b.Cipher != nil {
		c.AllowCipher(b.Cipher)
	}

	got, err := c.Check(jwt)
	assert.Nil(t, err)
	fmt.Println(got.String())
	assert.Equal(t, want, got.String())
}

func assertChecker(t *testing.T, b *Builder, want string) {
	iv := b.GenerateIV()
	assertCheckerWithIV(t, b, want, iv)
}

func TestChecker_Empty(t *testing.T) {
	b := NewBuilder()
	want := `{"Headers":{"alg":"none","typ":"JWT"},"Bodies":{}}`
	assertChecker(t, b, want)
}

func TestChecker_FullReservedClaims(t *testing.T) {
	b := createBuilderForTest("test")
	want := `{"Headers":{"alg":"none","typ":"JWT"},"Bodies":{"aud":["test","test"],"exp":1136217845,"iat":1136214245,"iss":"test","jti":"test","nbf":1136214245,"sub":"test"}}`
	assertChecker(t, b, want)
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
			want: `{"Headers":{"alg":"HS256","sid":"hs256","typ":"JWT"},"Bodies":{"aud":["HS256","HS256"],"exp":1136217845,"iat":1136214245,"iss":"HS256","jti":"HS256","nbf":1136214245,"sub":"HS256"}}`,
		},
		{
			id:   "hs384",
			name: "HS384",
			want: `{"Headers":{"alg":"HS384","sid":"hs384","typ":"JWT"},"Bodies":{"aud":["HS384","HS384"],"exp":1136217845,"iat":1136214245,"iss":"HS384","jti":"HS384","nbf":1136214245,"sub":"HS384"}}`,
		},
		{
			id:   "hs512",
			name: "HS512",
			want: `{"Headers":{"alg":"HS512","sid":"hs512","typ":"JWT"},"Bodies":{"aud":["HS512","HS512"],"exp":1136217845,"iat":1136214245,"iss":"HS512","jti":"HS512","nbf":1136214245,"sub":"HS512"}}`,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := signer.NewHMACSigner(tt.id, tt.name, []byte(tt.name))
			b := createBuilderForTest(tt.name).WithSigner(s)
			assertChecker(t, b, tt.want)
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
			want: `{"Headers":{"alg":"RS256","sid":"rs256","typ":"JWT"},"Bodies":{"aud":["RS256","RS256"],"exp":1136217845,"iat":1136214245,"iss":"RS256","jti":"RS256","nbf":1136214245,"sub":"RS256"}}`,
		},
		{
			id:   "rs384",
			name: "RS384",
			want: `{"Headers":{"alg":"RS384","sid":"rs384","typ":"JWT"},"Bodies":{"aud":["RS384","RS384"],"exp":1136217845,"iat":1136214245,"iss":"RS384","jti":"RS384","nbf":1136214245,"sub":"RS384"}}`,
		},
		{
			id:   "rs512",
			name: "RS512",
			want: `{"Headers":{"alg":"RS512","sid":"rs512","typ":"JWT"},"Bodies":{"aud":["RS512","RS512"],"exp":1136217845,"iat":1136214245,"iss":"RS512","jti":"RS512","nbf":1136214245,"sub":"RS512"}}`,
		},
		{
			id:   "ps256",
			name: "PS256",
			want: `{"Headers":{"alg":"PS256","sid":"ps256","typ":"JWT"},"Bodies":{"aud":["PS256","PS256"],"exp":1136217845,"iat":1136214245,"iss":"PS256","jti":"PS256","nbf":1136214245,"sub":"PS256"}}`,
		},
		{
			id:   "ps384",
			name: "PS384",
			want: `{"Headers":{"alg":"PS384","sid":"ps384","typ":"JWT"},"Bodies":{"aud":["PS384","PS384"],"exp":1136217845,"iat":1136214245,"iss":"PS384","jti":"PS384","nbf":1136214245,"sub":"PS384"}}`,
		},
		{
			id:   "ps512",
			name: "PS512",
			want: `{"Headers":{"alg":"PS512","sid":"ps512","typ":"JWT"},"Bodies":{"aud":["PS512","PS512"],"exp":1136217845,"iat":1136214245,"iss":"PS512","jti":"PS512","nbf":1136214245,"sub":"PS512"}}`,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := signer.NewRSASigner(tt.id, tt.name, test.RSAPrivateKey)
			b := createBuilderForTest(tt.name).WithSigner(s)
			assertChecker(t, b, tt.want)
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
			privateKey: test.ECDSAP256PrivateKey,
			want:       `{"Headers":{"alg":"ES256","sid":"es256","typ":"JWT"},"Bodies":{"aud":["ES256","ES256"],"exp":1136217845,"iat":1136214245,"iss":"ES256","jti":"ES256","nbf":1136214245,"sub":"ES256"}}`,
		},
		{
			id:         "es384",
			name:       "ES384",
			privateKey: test.ECDSAP384PrivateKey,
			want:       `{"Headers":{"alg":"ES384","sid":"es384","typ":"JWT"},"Bodies":{"aud":["ES384","ES384"],"exp":1136217845,"iat":1136214245,"iss":"ES384","jti":"ES384","nbf":1136214245,"sub":"ES384"}}`,
		},
		{
			id:         "es512",
			name:       "ES512",
			privateKey: test.ECDSAP521PrivateKey,
			want:       `{"Headers":{"alg":"ES512","sid":"es512","typ":"JWT"},"Bodies":{"aud":["ES512","ES512"],"exp":1136217845,"iat":1136214245,"iss":"ES512","jti":"ES512","nbf":1136214245,"sub":"ES512"}}`,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := signer.NewECDSASigner(tt.id, tt.name, tt.privateKey)
			b := createBuilderForTest(tt.name).WithSigner(s)
			assertChecker(t, b, tt.want)
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
			want: `{"Headers":{"alg":"none","cid":"a128cbc","enc":"A128CBC","iv":"NGtpYmF6ZW40a2liYXplbg","typ":"JWE"},"Bodies":{"aud":["A128CBC","A128CBC"],"exp":1136217845,"iat":1136214245,"iss":"A128CBC","jti":"A128CBC","nbf":1136214245,"sub":"A128CBC"}}`,
		},
		{
			id:   "a192cbc",
			name: "A192CBC",
			key:  "kibazencnA192CBCnA192CBC",
			want: `{"Headers":{"alg":"none","cid":"a192cbc","enc":"A192CBC","iv":"NGtpYmF6ZW40a2liYXplbg","typ":"JWE"},"Bodies":{"aud":["A192CBC","A192CBC"],"exp":1136217845,"iat":1136214245,"iss":"A192CBC","jti":"A192CBC","nbf":1136214245,"sub":"A192CBC"}}`,
		},
		{
			id:   "a256cbc",
			name: "A256CBC",
			key:  "kibazencnA256CBCkibazencnA256CBC",
			want: `{"Headers":{"alg":"none","cid":"a256cbc","enc":"A256CBC","iv":"NGtpYmF6ZW40a2liYXplbg","typ":"JWE"},"Bodies":{"aud":["A256CBC","A256CBC"],"exp":1136217845,"iat":1136214245,"iss":"A256CBC","jti":"A256CBC","nbf":1136214245,"sub":"A256CBC"}}`,
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cipher.NewAESCBCCipher(tt.id, []byte(tt.key))
			b := createBuilderForTest(tt.name).WithCipher(c)
			assertCheckerWithIV(t, b, tt.want, iv)
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
			want:      `{"Headers":{"alg":"HS256","cid":"hs256_a128cbc","enc":"A128CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs256_a128cbc","typ":"JWE"},"Bodies":{"aud":["hs256_a128cbc","hs256_a128cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs256_a128cbc","jti":"hs256_a128cbc","nbf":1136214245,"sub":"hs256_a128cbc"}}`,
		},
		{
			id:        "hs256_a192cbc",
			hmacName:  "HS256",
			aesCbcKey: "kibazencnA192CBCnA192CBC",
			want:      `{"Headers":{"alg":"HS256","cid":"hs256_a192cbc","enc":"A192CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs256_a192cbc","typ":"JWE"},"Bodies":{"aud":["hs256_a192cbc","hs256_a192cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs256_a192cbc","jti":"hs256_a192cbc","nbf":1136214245,"sub":"hs256_a192cbc"}}`,
		},
		{
			id:        "hs256_a256cbc",
			hmacName:  "HS256",
			aesCbcKey: "kibazencnA256CBCkibazencnA256CBC",
			want:      `{"Headers":{"alg":"HS256","cid":"hs256_a256cbc","enc":"A256CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs256_a256cbc","typ":"JWE"},"Bodies":{"aud":["hs256_a256cbc","hs256_a256cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs256_a256cbc","jti":"hs256_a256cbc","nbf":1136214245,"sub":"hs256_a256cbc"}}`,
		},
		{
			id:        "hs384_a128cbc",
			hmacName:  "HS384",
			aesCbcKey: "kibazencnA128CBC",
			want:      `{"Headers":{"alg":"HS384","cid":"hs384_a128cbc","enc":"A128CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs384_a128cbc","typ":"JWE"},"Bodies":{"aud":["hs384_a128cbc","hs384_a128cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs384_a128cbc","jti":"hs384_a128cbc","nbf":1136214245,"sub":"hs384_a128cbc"}}`,
		},
		{
			id:        "hs384_a192cbc",
			hmacName:  "HS384",
			aesCbcKey: "kibazencnA192CBCnA192CBC",
			want:      `{"Headers":{"alg":"HS384","cid":"hs384_a192cbc","enc":"A192CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs384_a192cbc","typ":"JWE"},"Bodies":{"aud":["hs384_a192cbc","hs384_a192cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs384_a192cbc","jti":"hs384_a192cbc","nbf":1136214245,"sub":"hs384_a192cbc"}}`,
		},
		{
			id:        "hs384_a256cbc",
			hmacName:  "HS384",
			aesCbcKey: "kibazencnA256CBCkibazencnA256CBC",
			want:      `{"Headers":{"alg":"HS384","cid":"hs384_a256cbc","enc":"A256CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs384_a256cbc","typ":"JWE"},"Bodies":{"aud":["hs384_a256cbc","hs384_a256cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs384_a256cbc","jti":"hs384_a256cbc","nbf":1136214245,"sub":"hs384_a256cbc"}}`,
		},
		{
			id:        "hs512_a128cbc",
			hmacName:  "HS512",
			aesCbcKey: "kibazencnA128CBC",
			want:      `{"Headers":{"alg":"HS512","cid":"hs512_a128cbc","enc":"A128CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs512_a128cbc","typ":"JWE"},"Bodies":{"aud":["hs512_a128cbc","hs512_a128cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs512_a128cbc","jti":"hs512_a128cbc","nbf":1136214245,"sub":"hs512_a128cbc"}}`,
		},
		{
			id:        "hs512_a192cbc",
			hmacName:  "HS512",
			aesCbcKey: "kibazencnA192CBCnA192CBC",
			want:      `{"Headers":{"alg":"HS512","cid":"hs512_a192cbc","enc":"A192CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs512_a192cbc","typ":"JWE"},"Bodies":{"aud":["hs512_a192cbc","hs512_a192cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs512_a192cbc","jti":"hs512_a192cbc","nbf":1136214245,"sub":"hs512_a192cbc"}}`,
		},
		{
			id:        "hs512_a256cbc",
			hmacName:  "HS512",
			aesCbcKey: "kibazencnA256CBCkibazencnA256CBC",
			want:      `{"Headers":{"alg":"HS512","cid":"hs512_a256cbc","enc":"A256CBC","iv":"NGtpYmF6ZW40a2liYXplbg","sid":"hs512_a256cbc","typ":"JWE"},"Bodies":{"aud":["hs512_a256cbc","hs512_a256cbc"],"exp":1136217845,"iat":1136214245,"iss":"hs512_a256cbc","jti":"hs512_a256cbc","nbf":1136214245,"sub":"hs512_a256cbc"}}`,
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			s := signer.NewHMACSigner(tt.id, tt.hmacName, []byte(tt.hmacName))
			c := cipher.NewAESCBCCipher(tt.id, []byte(tt.aesCbcKey))
			b := createBuilderForTest(tt.id).WithSigner(s).WithCipher(c)
			assertCheckerWithIV(t, b, tt.want, iv)
		})
	}
}
