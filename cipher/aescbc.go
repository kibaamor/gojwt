package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/kibaamor/gojwt/utils"
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

func (c *aesCBCCipher) ID() string {
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

func (c *aesCBCCipher) Encrypt(data, iv []byte) ([]byte, error) {
	if len(iv) != c.block.BlockSize() {
		return nil, errAESCBCIV
	}

	data = utils.PKCS7Padding(data, c.block.BlockSize())
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
	return utils.PKCS7Unpadding(data)
}

func NewAESCBCCipher(id string, key []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher/aescbc: invalid aes key: '%w'", err)
	}
	return &aesCBCCipher{
		id:      id,
		name:    fmt.Sprintf("A%dCBC", len(key)*8),
		keySize: len(key),
		block:   block,
	}, nil
}
