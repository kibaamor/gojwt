//go:build test || unit

package gojwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/kibaamor/gojwt/claims"

	"github.com/stretchr/testify/assert"

	"github.com/kibaamor/gojwt/cipher"
	"github.com/kibaamor/gojwt/internal/test"
	"github.com/kibaamor/gojwt/signer"
)

var nowForTest time.Time

func init() {
	var err error
	nowForTest, err = time.Parse("2006-01-02T15:04:05", "2006-01-02T15:04:05")
	if err != nil {
		panic(err)
	}
}

func timeFuncForTest() time.Time {
	return nowForTest
}

func ivGeneratorForTest(iv []byte) func(int) []byte {
	return func(int) []byte {
		return iv
	}
}

func createBuilderForTest(name string) *Builder {
	now := nowForTest

	b := NewBuilder()
	b.
		WithIssuer(name).
		WithSubject(name).
		AddAudience(name).
		AddAudience(name + name).
		WithExpiresAt(now.Add(time.Hour)).
		WithNotBefore(now).
		WithIssuedAt(now).
		WithJwtID(name)

	return b
}

func assertSign(t *testing.T, b *Builder, signature string) {
	sig, err := b.Sign()
	assert.Nil(t, err)
	assert.Equal(t, signature, sig)
}

func splitDataAndSignatureFromJWT(t *testing.T, jwt string) (data, sig []byte, ok bool) {
	segments := strings.SplitN(jwt, ".", 3)
	if !assert.Equal(t, 3, len(segments)) {
		return data, sig, ok
	}

	if len(segments[2]) == 0 {
		data = []byte(jwt[:len(jwt)-1])
		sig = []byte{}
		ok = true
		return data, sig, ok
	}

	var err error
	sig, err = base64.RawURLEncoding.DecodeString(segments[2])
	if !assert.Nil(t, err) {
		return data, sig, ok
	}

	data = []byte(jwt[:len(jwt)-len(segments[2])-1])
	ok = true
	return data, sig, ok
}

func TestBuilder_Empty(t *testing.T) {
	b := NewBuilder()
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
}

func TestBuilder_AddAudience(t *testing.T) {
	b := NewBuilder()

	b.AddAudience("1")
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWRpZW5jZSI6WyIxIl19.")

	b.AddAudience("2")
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWRpZW5jZSI6WyIxIiwiMiJdfQ.")
}

func TestBuilder_FullReservedClaims(t *testing.T) {
	b := createBuilderForTest("test")
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiJ0ZXN0IiwiaXNzdWVyIjoidGVzdCIsInN1YmplY3QiOiJ0ZXN0IiwiYXVkaWVuY2UiOlsidGVzdCIsInRlc3R0ZXN0Il0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.")
}

func TestBuilder_HMAC(t *testing.T) {
	tests := []struct {
		id   string
		name string
		want string
	}{
		{
			id:   "hs256",
			name: "HS256",
			want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsInNpZCI6ImhzMjU2In0.eyJqdGkiOiJIUzI1NiIsImlzc3VlciI6IkhTMjU2Iiwic3ViamVjdCI6IkhTMjU2IiwiYXVkaWVuY2UiOlsiSFMyNTYiLCJIUzI1NkhTMjU2Il0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.jRXM3W74OK7zfuLwKnktFx3mYapQ-uem1dvI_6icNbY",
		},
		{
			id:   "hs384",
			name: "HS384",
			want: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsInNpZCI6ImhzMzg0In0.eyJqdGkiOiJIUzM4NCIsImlzc3VlciI6IkhTMzg0Iiwic3ViamVjdCI6IkhTMzg0IiwiYXVkaWVuY2UiOlsiSFMzODQiLCJIUzM4NEhTMzg0Il0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.vNVczCR8xvRuKck-ixiyIiXOyiwDftm6LNPvKQAs-xpoFKtUzYF9fH5XZri1Kj16",
		},
		{
			id:   "hs512",
			name: "HS512",
			want: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsInNpZCI6ImhzNTEyIn0.eyJqdGkiOiJIUzUxMiIsImlzc3VlciI6IkhTNTEyIiwic3ViamVjdCI6IkhTNTEyIiwiYXVkaWVuY2UiOlsiSFM1MTIiLCJIUzUxMkhTNTEyIl0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.HYV9oqvhWEFKExclVPl2sF2OvlP83dljdwnBKW2Z2Hd53OPcQxTD1Z9ZrtT0kRHklRMhI9HTtjG0ytTNMdhy7A",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := signer.NewHMACSigner(tt.id, tt.name, []byte(tt.name))
			assert.Nil(t, err)
			b := createBuilderForTest(tt.name).WithSigner(s)

			jwt, err := b.Sign()
			assert.Nil(t, err)
			assert.Equal(t, tt.want, jwt)

			data, sig, ok := splitDataAndSignatureFromJWT(t, jwt)
			if !ok {
				return
			}

			v := s.Verifier()
			err = v.Verify(data, sig)
			assert.Nil(t, err)
		})
	}
}

func TestBuilder_RSA(t *testing.T) {
	tests := []struct {
		id   string
		name string
		want string
	}{
		{
			id:   "rs256",
			name: "RS256",
			want: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInNpZCI6InJzMjU2In0.eyJqdGkiOiJSUzI1NiIsImlzc3VlciI6IlJTMjU2Iiwic3ViamVjdCI6IlJTMjU2IiwiYXVkaWVuY2UiOlsiUlMyNTYiLCJSUzI1NlJTMjU2Il0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.BT864vzldU6ruO1W_qU7E59jF0z9s45PqxsodIS-lEQLaBkx3OvPEfeAW_xcEo1W9sbT1QW_q7-7YrPGgalqAn34p9wAy7zPg3_VpxVoisdBjECfz5nFqwiuKzq3VUOgX305wgQB--NnmGda-ryZDRrWvzoodociIT87Ne_Qazqrnjz_Ywc0Ja1SztkcBDdxal3tIWkx2IIaqWIG86RLNOTNRash7wOQNQYcQ69rEYOBxANVUIzWywnXssHk8v2DP-88WUZ1Fhy7rsXi2QzIEEhRHIKxriw4E7SEqeMhuDGpxb4UJv3EfS0iR7BgZjfzWHki-EMz9BOkytYusSYbvA",
		},
		{
			id:   "rs384",
			name: "RS384",
			want: "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsInNpZCI6InJzMzg0In0.eyJqdGkiOiJSUzM4NCIsImlzc3VlciI6IlJTMzg0Iiwic3ViamVjdCI6IlJTMzg0IiwiYXVkaWVuY2UiOlsiUlMzODQiLCJSUzM4NFJTMzg0Il0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.K853zRY6MmqzM8N-v4rVaUsV8YVNgdIgj_tniIxGGvL49_ui3-SGVV-QZLEOTJNC2XjMMEJqMIrYJg5QhO95XRp5NIsi1tD4a8Rm4lU3PmbHFcxHlpLZu7IlL7QvmR8HIb-gMddyOHov-PhKGK_1zixG5YgGg0-Pabgcu5a2Zpk3CieSs42g4X3TIOW8pLDHClr8rbym-V0ebyx6QKPxeoeIZG7_VFwRpnXya4RzztFro10TNFmDVLnhFLVcAkG84m1i9LTOxswywrjOLj1REOQg7XY8HqVzia3nwxxWIvpJHmA5jnzwCvWhn7b8kNssdxpznOTlgV80kKd9Zlk7JQ",
		},
		{
			id:   "rs512",
			name: "RS512",
			want: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsInNpZCI6InJzNTEyIn0.eyJqdGkiOiJSUzUxMiIsImlzc3VlciI6IlJTNTEyIiwic3ViamVjdCI6IlJTNTEyIiwiYXVkaWVuY2UiOlsiUlM1MTIiLCJSUzUxMlJTNTEyIl0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDV9.Ea8OuBLdw6VNEQpNnmk_RNs5D06gLLCnC_hNuRKxjOiNLRHH1bW64cH0-Ow4NwabXbkGcqD_fDjZC3c06oqImm0pKDswmMox8tbNpH0_ePJTmlZuWthFQUL6Cdirws1z8yJseq6QR0OzD5t0ADbWHUj91CFVbI1OxKcv55uD1mGSiYNhXtqzQlMZhGfiXtxKAo1TIChRar63I0pH14IjTBf2v5I3Ci-gF62M95ZIUB2apbmvzCo40wfRXZQPVxtakAVQjDtvK1OVnQ4YGfOkWB4d6LUTfHlf1ICnrFl27MnhqgKM546LErJSShNPPAxrT9jvZ0pI69Sm27nOhFvVnw",
		},
		{
			id:   "ps256",
			name: "PS256",
			want: "",
		},
		{
			id:   "ps384",
			name: "PS384",
			want: "",
		},
		{
			id:   "ps512",
			name: "PS512",
			want: "",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := signer.NewRSASigner(tt.id, tt.name, test.RSAPrivateKey)
			assert.Nil(t, err)
			b := createBuilderForTest(tt.name).WithSigner(s)

			jwt, err := b.Sign()
			assert.Nil(t, err)
			if len(tt.want) > 0 {
				assert.Equal(t, tt.want, jwt)
			}

			data, sig, ok := splitDataAndSignatureFromJWT(t, jwt)
			if !ok {
				return
			}

			v := s.Verifier()
			err = v.Verify(data, sig)
			assert.Nil(t, err)

			v, err = signer.NewRSAVerifier(tt.id, tt.name, test.RSAPublicKey)
			assert.Nil(t, err)
			err = v.Verify(data, sig)
			assert.Nil(t, err)
		})
	}
}

func TestBuilder_ECDSA(t *testing.T) {
	tests := []struct {
		id         string
		name       string
		privateKey *ecdsa.PrivateKey
		publicKey  *ecdsa.PublicKey
	}{
		{
			id:         "es256",
			name:       "ES256",
			privateKey: test.ECDSAP256PrivateKey,
			publicKey:  test.ECDSAP256PublicKey,
		},
		{
			id:         "es384",
			name:       "ES384",
			privateKey: test.ECDSAP384PrivateKey,
			publicKey:  test.ECDSAP384PublicKey,
		},
		{
			id:         "es512",
			name:       "ES512",
			privateKey: test.ECDSAP521PrivateKey,
			publicKey:  test.ECDSAP521PublicKey,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := signer.NewECDSASigner(tt.id, tt.name, tt.privateKey)
			assert.Nil(t, err)
			b := createBuilderForTest(tt.name).WithSigner(s)

			jwt, err := b.Sign()
			assert.Nil(t, err)

			data, sig, ok := splitDataAndSignatureFromJWT(t, jwt)
			if !ok {
				return
			}

			v := s.Verifier()
			err = v.Verify(data, sig)
			assert.Nil(t, err)

			v, err = signer.NewECDSAVerifier(tt.id, tt.name, tt.publicKey)
			assert.Nil(t, err)
			err = v.Verify(data, sig)
			assert.Nil(t, err)
		})
	}
}

func TestBuilder_AESCBC(t *testing.T) {
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
			want: "eyJhbGciOiJub25lIiwiZW5jIjoiQTEyOENCQyIsInR5cCI6IkpXRSIsImNpZCI6ImExMjhjYmMiLCJpdiI6Ik5HdHBZbUY2Wlc0MGEybGlZWHBsYmcifQ.NzHb2rLC8So8sOuDWcMolLg5qp-i4a8tsKlSNSOpFOhpoU6LLnTGi0JwaGuITwDkUkeet_J6q32aQ0CMUMV4MwVnsiat7L7lO5Rjmv81xxtw_EfUx_QAJmxU6ZAK_e9y2AJ3c9tayjzs8KnyxLROkxBfAuak4P1QAfT0ji-ljSbsKQ5_dUl5ZNhyfBXBLJOhzLUH4hSdBOKHhpeyg5H0tg.",
		},
		{
			id:   "a192cbc",
			name: "A192CBC",
			key:  "kibazencnA192CBCnA192CBC",
			want: "eyJhbGciOiJub25lIiwiZW5jIjoiQTE5MkNCQyIsInR5cCI6IkpXRSIsImNpZCI6ImExOTJjYmMiLCJpdiI6Ik5HdHBZbUY2Wlc0MGEybGlZWHBsYmcifQ.ZsXVAoAfpGfH-IghvT431R0hOSaM1zUIf3K9Q7OsFu__cg3Tu8u0C3QF2_-Xc3T3l9D-6li5Xybf2ZKdkEOMaW22EzfLOngGqfftbBfSFl6OrorxhUV-NAxpQETSVEh9GFN9a2WI7E7Pwu6WgAU99GXDGDb-U4nDQIpbXIHhNRcGJDoH7g7re4zzLLTc6744P4o_Il6L9Rh0SirJEiQ_tQ.",
		},
		{
			id:   "a256cbc",
			name: "A256CBC",
			key:  "kibazencnA256CBCkibazencnA256CBC",
			want: "eyJhbGciOiJub25lIiwiZW5jIjoiQTI1NkNCQyIsInR5cCI6IkpXRSIsImNpZCI6ImEyNTZjYmMiLCJpdiI6Ik5HdHBZbUY2Wlc0MGEybGlZWHBsYmcifQ.Bpm2oVTr6Zz_JD4f-05rAIf4FESyDln_nRugv5mtxkwqsRsaKfAL8x-xBeVL8KBIx3f27dUPt3xYHr68beMALdglIeZNFIYmURdAKN-Uy283mznHmSrKzWRIOsFjdEr6HEzZpaiLHNzbl3vOH6WHjb-ZVmwxc9umLOrL_0WwwIf7aqgzSjRvRQZ3OAnzTrp9YCnmkQwYIq88131LgoUdhA.",
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := cipher.NewAESCBCCipher(tt.id, []byte(tt.key))
			assert.Nil(t, err)
			b := createBuilderForTest(tt.name).WithCipher(c).WithIVGenerator(ivGeneratorForTest(iv))

			jwt, err := b.Sign()
			assert.Nil(t, err)
			assert.Equal(t, tt.want, jwt)
		})
	}
}

type CustomHeader struct {
	claims.BasicHeader
	CustomHeaderField string
}

type CustomBody struct {
	claims.BasicBody
	CustomBodyField string
}

func TestBuilder_CustomToken(t *testing.T) {
	b := NewBuildWithToken(Token{
		Header: &CustomHeader{
			CustomHeaderField: "custom header value",
		},
		Body: &CustomBody{
			CustomBodyField: "custom body value",
		},
	})

	name := "CustomToken"
	now := nowForTest
	b.
		WithIssuer(name).
		WithSubject(name).
		AddAudience(name).
		AddAudience(name + name).
		WithExpiresAt(now.Add(time.Hour)).
		WithNotBefore(now).
		WithIssuedAt(now).
		WithJwtID(name)

	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwiQ3VzdG9tSGVhZGVyRmllbGQiOiJjdXN0b20gaGVhZGVyIHZhbHVlIn0.eyJqdGkiOiJDdXN0b21Ub2tlbiIsImlzc3VlciI6IkN1c3RvbVRva2VuIiwic3ViamVjdCI6IkN1c3RvbVRva2VuIiwiYXVkaWVuY2UiOlsiQ3VzdG9tVG9rZW4iLCJDdXN0b21Ub2tlbkN1c3RvbVRva2VuIl0sImV4cCI6MTEzNjIxNzg0NSwibmJmIjoxMTM2MjE0MjQ1LCJpYXQiOjExMzYyMTQyNDUsIkN1c3RvbUJvZHlGaWVsZCI6ImN1c3RvbSBib2R5IHZhbHVlIn0.")
}
