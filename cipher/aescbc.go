package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/kibaamor/gojwt/util"
	"io"
)

var (
	errAESCBCIV   = errors.New("cipher/aescbc: invalid iv")
	errAESCBCData = errors.New("cipher/aescbc: invalid data")
)

type aesCBCCipher struct {
	id      string
	name    string
	keySize int
	block   cipher.Block
}

func (c *aesCBCCipher) Id() string {
	return c.id
}

func (c *aesCBCCipher) Name() string {
	return c.name
}

func (c *aesCBCCipher) KeySize() int {
	return c.keySize
}

func (c *aesCBCCipher) IVSize() int {
	return c.block.BlockSize()
}

func (c *aesCBCCipher) GenerateIV() []byte {
	iv := make([]byte, c.block.BlockSize())
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	return iv
}

func (c *aesCBCCipher) Encrypt(data, iv []byte) ([]byte, error) {
	if len(iv) != c.block.BlockSize() {
		return nil, errAESCBCIV
	}

	data = util.PKCS7Padding(data, c.block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(c.block, iv)
	blockMode.CryptBlocks(data, data)
	return data, nil
}

func (c *aesCBCCipher) Decrypt(data, iv []byte) ([]byte, error) {
	if len(data)%c.block.BlockSize() != 0 {
		return nil, errAESCBCData
	}
	if len(iv) != c.block.BlockSize() {
		return nil, errAESCBCIV
	}

	blockMode := cipher.NewCBCDecrypter(c.block, iv)
	blockMode.CryptBlocks(data, data)
	return util.PKCS7Unpadding(data)
}

func NewAESCBCCipher(id string, key []byte) Cipher {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("cipher/aescbc: invalid aes key: '%v'", err.Error()))
	}
	return &aesCBCCipher{
		id:      id,
		name:    fmt.Sprintf("A%dCBC", len(key)*8),
		keySize: len(key),
		block:   block,
	}
}
