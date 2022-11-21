package gojwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"github.com/kibaamor/gojwt/cipher"
	"github.com/kibaamor/gojwt/internal/test"
	"github.com/kibaamor/gojwt/signer"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func createBuilderForTest(name string) *Builder {
	now, err := time.Parse("2006-01-02T15:04:05", "2006-01-02T15:04:05")
	if err != nil {
		panic(err)
	}

	b := NewBuilder()
	b.
		WithIssuer(name).
		WithSubject(name).
		AddAudience(name).
		AddAudience(name).
		WithExpiresAt(now.Add(time.Hour)).
		WithNotBefore(now).
		WithIssuedAt(now).
		WithJwtId(name)

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
		return
	}

	if len(segments[2]) == 0 {
		data = []byte(jwt[:len(jwt)-1])
		sig = []byte{}
		ok = true
		return
	}

	var err error
	sig, err = base64.RawURLEncoding.DecodeString(segments[2])
	if !assert.Nil(t, err) {
		return
	}

	data = []byte(jwt[:len(jwt)-len(segments[2])-1])
	ok = true
	return
}

func TestBuilder_Empty(t *testing.T) {
	b := NewBuilder()
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
}

func TestBuilder_AddAudience(t *testing.T) {
	b := NewBuilder()

	b.AddAudience("1")
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiMSJdfQ.")

	b.AddAudience("2")
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiMSIsIjIiXX0.")
}

func TestBuilder_FullReservedClaims(t *testing.T) {
	b := createBuilderForTest("test")
	assertSign(t, b, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdCIsInRlc3QiXSwiZXhwIjoxMTM2MjE3ODQ1LCJpYXQiOjExMzYyMTQyNDUsImlzcyI6InRlc3QiLCJqdGkiOiJ0ZXN0IiwibmJmIjoxMTM2MjE0MjQ1LCJzdWIiOiJ0ZXN0In0.")
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
			want: "eyJhbGciOiJIUzI1NiIsInNpZCI6ImhzMjU2IiwidHlwIjoiSldUIn0.eyJhdWQiOlsiSFMyNTYiLCJIUzI1NiJdLCJleHAiOjExMzYyMTc4NDUsImlhdCI6MTEzNjIxNDI0NSwiaXNzIjoiSFMyNTYiLCJqdGkiOiJIUzI1NiIsIm5iZiI6MTEzNjIxNDI0NSwic3ViIjoiSFMyNTYifQ.2d1td_ZLU1Bvr2J-4loKPIS9Ryj7sFyAUYBzbZ8mPF4",
		},
		{
			id:   "hs384",
			name: "HS384",
			want: "eyJhbGciOiJIUzM4NCIsInNpZCI6ImhzMzg0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsiSFMzODQiLCJIUzM4NCJdLCJleHAiOjExMzYyMTc4NDUsImlhdCI6MTEzNjIxNDI0NSwiaXNzIjoiSFMzODQiLCJqdGkiOiJIUzM4NCIsIm5iZiI6MTEzNjIxNDI0NSwic3ViIjoiSFMzODQifQ.5ft6mLML7OAPOXy5yMBwmkAIC2FXLzkyxwmOSKxDkdn-ss8tFsTtg4HFTIBpt0bA",
		},
		{
			id:   "hs512",
			name: "HS512",
			want: "eyJhbGciOiJIUzUxMiIsInNpZCI6ImhzNTEyIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiSFM1MTIiLCJIUzUxMiJdLCJleHAiOjExMzYyMTc4NDUsImlhdCI6MTEzNjIxNDI0NSwiaXNzIjoiSFM1MTIiLCJqdGkiOiJIUzUxMiIsIm5iZiI6MTEzNjIxNDI0NSwic3ViIjoiSFM1MTIifQ.dbOgChul2KTlpGbuvDcu7lNmlxq-ZPBET1ec4h0_TD4wi7nI6m6LYniN4ZY1LxbY985C1mZnCcwtndWsw5pU7A",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := signer.NewHMACSigner(tt.id, tt.name, []byte(tt.name))
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
			want: "eyJhbGciOiJSUzI1NiIsInNpZCI6InJzMjU2IiwidHlwIjoiSldUIn0.eyJhdWQiOlsiUlMyNTYiLCJSUzI1NiJdLCJleHAiOjExMzYyMTc4NDUsImlhdCI6MTEzNjIxNDI0NSwiaXNzIjoiUlMyNTYiLCJqdGkiOiJSUzI1NiIsIm5iZiI6MTEzNjIxNDI0NSwic3ViIjoiUlMyNTYifQ.JGo5gAj8e8XMM37qt_v9mZZOSMJAz_XcZydFzrH_EksIF-D7DbPEY8H07PtWcJs9SWYv-J-waOedMFKu9u9n3CWQl4n4-rnirNyWtO1O-n_OCDohA2xzlQlibiGgVLn3kJjGcCudcD3mIsoa9GzB1OwnNlkCYH9_rzLBORtU3hzQ_VfIV_2DBb0nxdlCHJPBIoRYH-idoG8NsTaPH_ShV-1AB16DtossGa9XKkVYHFG2YZ0eCgTdDobRdfO61oUD41FsaQNiKJsrph_QK2TE5Baaio43yIVBDqVYS6GACno0eQssvu9wLRkw-7tXNdxAbWNUEOlh_ufL-T2lq4IsoA",
		},
		{
			id:   "rs384",
			name: "RS384",
			want: "eyJhbGciOiJSUzM4NCIsInNpZCI6InJzMzg0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsiUlMzODQiLCJSUzM4NCJdLCJleHAiOjExMzYyMTc4NDUsImlhdCI6MTEzNjIxNDI0NSwiaXNzIjoiUlMzODQiLCJqdGkiOiJSUzM4NCIsIm5iZiI6MTEzNjIxNDI0NSwic3ViIjoiUlMzODQifQ.NO4UEVDWR47_IzH7YZIC7tIJhDjpMBbEnDTHPChLRFbhjUcH7GF5VpxMsrOYkOLIMv8PKhFev3IWqNVh5dz2eMF9JjgpwBON073cu3wSLdnqeVwBLiHvbjvYUqcpTuF3T8aChOMFj2jeBG1jtXFpgX9-8a6LxwVQxJVxF5ftg62Y2wkN7QdR2zjDV0cR7cMFzqKMMSqtkRNpYMR8LYj76eNmLxcrrjg8ioSjAJMOxxYBHGgTbd13b-0tygShRr2uE_YWOPCXSBpWWD6svNqPGBxsAd2tUqv0Yi3qSxyIDFHRrehjVi_ueukC2_JkezDLKQotX81d6YDzbcOsUDzPpQ",
		},
		{
			id:   "rs512",
			name: "RS512",
			want: "eyJhbGciOiJSUzUxMiIsInNpZCI6InJzNTEyIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiUlM1MTIiLCJSUzUxMiJdLCJleHAiOjExMzYyMTc4NDUsImlhdCI6MTEzNjIxNDI0NSwiaXNzIjoiUlM1MTIiLCJqdGkiOiJSUzUxMiIsIm5iZiI6MTEzNjIxNDI0NSwic3ViIjoiUlM1MTIifQ.Bqt9ovk_xulQOhfJ1zWH9pGFwIfGzWUoOBdQ8ecDLRpCcU-B_5fGMu_2cpa0ZJqpNHGpjTJ8rGTrBNoRxSQX31MXlUpCla_-xjd9LuArpvcZsqaREKGeIU7oKByk3pMAx42ZLp6_fYatcuSRbrCG2NIrVXHsty3wsKSBgIW1V9E70i6gIOyPzhwc6v6O0Jc5jxPsackHzU-tdnoVGYfa1QxIaLixE19jpdtC8TCX_yp3rwWo98lY-Nbt-ubQ8t3nxY1Lv0XJaKEnCsLZdsrVdgnEMfM7mmAsssmSeKvcZAwYYV-_1dn31YMZ2OPPVRA6v520VREffeAhiTr__z2cdA",
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
			s := signer.NewRSASigner(tt.id, tt.name, test.RSAPrivateKey)
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

			v = signer.NewRSAVerifier(tt.id, tt.name, test.RSAPublicKey)
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
			s := signer.NewECDSASigner(tt.id, tt.name, tt.privateKey)
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

			v = signer.NewECDSAVerifier(tt.id, tt.name, tt.publicKey)
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
			want: "eyJhbGciOiJub25lIiwiY2lkIjoiYTEyOGNiYyIsImVuYyI6IkExMjhDQkMiLCJpdiI6Ik5HdHBZbUY2Wlc0MGEybGlZWHBsYmciLCJ0eXAiOiJKV0UifQ.ZoPUa6anEdWCo1sKNjIyAwgUd9yBXbkGcrsbUnsjhh7IoTRf5KGKdydECZOwxqldLU8AkkoKgu5Z9-bTwAAZKR2Iu7UUnWN-GkMG3Q-UIjbS2z2HmKLzqKw5HHnDNbij8mz14pii3982hl7Lb3tZSW9VYUfdbP0Ap-RBBPTRtf-g0494VepS7maNpJ5lyybu.",
		},
		{
			id:   "a192cbc",
			name: "A192CBC",
			key:  "kibazencnA192CBCnA192CBC",
			want: "eyJhbGciOiJub25lIiwiY2lkIjoiYTE5MmNiYyIsImVuYyI6IkExOTJDQkMiLCJpdiI6Ik5HdHBZbUY2Wlc0MGEybGlZWHBsYmciLCJ0eXAiOiJKV0UifQ.6wBllF4hRQZYeksho-Fb6rsH70sqFZJ-DAksHLaSwat01H03AsgglBZl_KFG3TT56BnduKRbZQEfoKJN4suZZ1dVQi-gUas7FakwFGjNUva1KX25zmnvHpPHAuiiVcm9HeZcbGbdgnP-_qzQtAFqd_DZtha-VrfM7kD66XtcHb99JQpkC9OHZ-hl6DjyqAU1.",
		},
		{
			id:   "a256cbc",
			name: "A256CBC",
			key:  "kibazencnA256CBCkibazencnA256CBC",
			want: "eyJhbGciOiJub25lIiwiY2lkIjoiYTI1NmNiYyIsImVuYyI6IkEyNTZDQkMiLCJpdiI6Ik5HdHBZbUY2Wlc0MGEybGlZWHBsYmciLCJ0eXAiOiJKV0UifQ.xtyCdCqmM4QPaF0ZYIHnkNii3pVBAtUu3wmZCKAocLZHb5ROJ_9Wl7BBTQR8sH2yzcCTameEeM_98wH9-ryqSbegpVj-1jqM6I3TWqaK2h8eBn9MrdsWkEaO5XCv7K3yZkeNCiolIVP5C8o6L3JgW53qO_tISUPPbOpicCBgu0KqczJTo_lu-gwY8dlib3F9.",
		},
	}

	iv := []byte("4kibazen4kibazen")

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cipher.NewAESCBCCipher(tt.id, []byte(tt.key))
			b := createBuilderForTest(tt.name).WithCipher(c)

			jwt, err := b.SignWithIV(iv)
			assert.Nil(t, err)
			assert.Equal(t, tt.want, jwt)
		})
	}
}
