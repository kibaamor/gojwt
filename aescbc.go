package gojwt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/kibaamor/gojwt/internal/utils"
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
		return nil, fmt.Errorf("gojwt/aescbc: invalid iv. the length of iv: '%d', block size: '%d'",
			len(iv), c.block.BlockSize())
	}

	data = utils.PKCS7Padding(data, c.block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(c.block, iv)
	blockMode.CryptBlocks(data, data)
	return data, nil
}

func (c *aesCBCCipher) Decrypt(data, iv []byte) ([]byte, error) {
	if len(data)%c.block.BlockSize() != 0 {
		return nil, fmt.Errorf("gojwt/aescbc: invalid data. the length of data: '%d', block size: '%d'",
			len(data), c.block.BlockSize())
	}
	if len(iv) != c.block.BlockSize() {
		return nil, fmt.Errorf("gojwt/aescbc: invalid iv. the length of iv: '%d', block size: '%d'",
			len(iv), c.block.BlockSize())
	}

	blockMode := cipher.NewCBCDecrypter(c.block, iv)
	blockMode.CryptBlocks(data, data)
	return utils.PKCS7Unpadding(data)
}

func NewAESCBCCipher(id string, key []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gojwt/aescbc: invalid aes key: '%w'", err)
	}
	return &aesCBCCipher{
		id:      id,
		name:    fmt.Sprintf("A%dCBC", len(key)*8),
		keySize: len(key),
		block:   block,
	}, nil
}
