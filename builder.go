package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"github.com/kibaamor/gojwt/cipher"
	"github.com/kibaamor/gojwt/signer"
	"github.com/kibaamor/gojwt/util"
)

type Builder struct {
	*Token
	Signer signer.Signer
	Cipher cipher.Cipher
}

func NewBuilder() *Builder {
	return &Builder{
		Token: NewToken(),
	}
}

func (b *Builder) WithCipher(cipher cipher.Cipher) *Builder {
	b.Cipher = cipher
	return b
}

func (b *Builder) WithSigner(signer signer.Signer) *Builder {
	b.Signer = signer
	return b
}

func (b *Builder) GenerateIV() []byte {
	var iv []byte
	if b.Cipher != nil {
		iv = util.RandBytes(b.Cipher.IVSize())
	}
	return iv
}

func (b *Builder) Sign() (string, error) {
	return b.SignWithIV(b.GenerateIV())
}

func (b *Builder) SignWithIV(iv []byte) (string, error) {
	if b.Signer == nil {
		b.setAlgorithmNone()
	} else {
		b.setAlgorithm(b.Signer.Name()).
			setSignerId(b.Signer.Id())
	}

	var enc = base64.RawURLEncoding

	if b.Cipher == nil {
		b.setTypeJWT()
	} else {
		b.setTypeJWE().
			setEncryption(b.Cipher.Name()).
			setCipherId(b.Cipher.Id())
		if len(iv) > 0 {
			b.setIV(enc.EncodeToString(iv))
		}
	}

	headers, err := json.Marshal(b.Headers)
	if err != nil {
		return "", err
	}

	bodies, err := json.Marshal(b.Bodies)
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
		return "", nil
	}

	encodedSignature := util.RawURLEncode(signature)

	return string(append(jwtWithoutSignature, encodedSignature...)), nil
}
