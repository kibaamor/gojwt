package gojwt

import (
	"encoding/base64"
	"encoding/json"
)

// https://www.rfc-editor.org/rfc/rfc7519.html#page-18
const (
	NoneAlgNameAbbr = "none"
	JWTNameAbbr     = "JWT"
	JWENameAbbr     = "JWE"
)

type Builder struct {
	Token
	Signer      Signer
	Cipher      Cipher
	IVGenerator func(int) []byte
}

func NewBasicBuilder() *Builder {
	return NewBuildWithToken(NewBasicToken())
}

func NewBuildWithToken(token Token) *Builder {
	return &Builder{Token: token}
}

func (b *Builder) WithSigner(s Signer) *Builder {
	b.Signer = s
	return b
}

func (b *Builder) WithCipher(c Cipher) *Builder {
	b.Cipher = c
	return b
}

func (b *Builder) WithIVGenerator(f func(int) []byte) *Builder {
	b.IVGenerator = f
	return b
}

func (b *Builder) GenerateIV() []byte {
	ivSize := b.Cipher.IVSize()
	if b.IVGenerator != nil {
		return b.IVGenerator(ivSize)
	}
	return RandBytes(ivSize)
}

func (b *Builder) Sign() (string, error) {
	if b.Signer == nil {
		b.Header.SetAlgorithm(NoneAlgNameAbbr)
	} else {
		b.Header.SetAlgorithm(b.Signer.Name())
		b.Header.SetSignerID(b.Signer.ID())
	}

	var enc = base64.RawURLEncoding
	var iv []byte

	if b.Cipher == nil {
		b.Header.SetType(JWTNameAbbr)
	} else {
		iv = b.GenerateIV()

		b.Header.SetType(JWENameAbbr)
		b.Header.SetEncryption(b.Cipher.Name())
		b.Header.SetCipherID(b.Cipher.ID())
		b.Header.SetIV(enc.EncodeToString(iv))
	}

	headers, err := json.Marshal(b.Header)
	if err != nil {
		return "", err
	}

	bodies, err := json.Marshal(b.Body)
	if err != nil {
		return "", err
	}

	if b.Cipher != nil {
		bodies, err = b.Cipher.Encrypt(bodies, iv)
		if err != nil {
			return "", err
		}
	}

	// data: header + "." + bodies
	// jwt: data + "." + signature
	encodedHeadersLen := enc.EncodedLen(len(headers))
	encodedClaimsLen := enc.EncodedLen(len(bodies))
	dataLen := encodedHeadersLen + 1 + encodedClaimsLen

	// jwtWithoutSignature: data + "."
	jwtWithoutSignature := make([]byte, dataLen+1)
	bufHeaders := jwtWithoutSignature[:encodedHeadersLen]
	jwtWithoutSignature[encodedHeadersLen] = '.'
	bufBodies := jwtWithoutSignature[encodedHeadersLen+1 : dataLen]
	jwtWithoutSignature[dataLen] = '.'

	enc.Encode(bufHeaders, headers)
	enc.Encode(bufBodies, bodies)

	if b.Signer == nil {
		return string(jwtWithoutSignature), nil
	}

	signature, err := b.Signer.Sign(jwtWithoutSignature[:dataLen])
	if err != nil {
		return "", err
	}

	encodedSignature := RawURLEncode(signature)

	return string(append(jwtWithoutSignature, encodedSignature...)), nil
}
