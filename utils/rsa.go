package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

var (
	errInvalidRSAPrivateKeyData = errors.New("utils/rsa: invalid RSA private key")
	errInvalidRSAPublicKeyData  = errors.New("utils/rsa: invalid RSA public key")
)

func ParseRSAPrivateKeyFromBytes(data []byte) (*rsa.PrivateKey, error) {
	var (
		parsedKey interface{}
		err       error
	)

	if parsedKey, err = x509.ParsePKCS1PrivateKey(data); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(data); err != nil {
			return nil, err
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errInvalidRSAPrivateKeyData
	}

	return privateKey, privateKey.Validate()
}

func ParseRSAPublicKeyFromBytes(data []byte) (*rsa.PublicKey, error) {
	var (
		parsedKey interface{}
		err       error
	)

	if parsedKey, err = x509.ParsePKCS1PublicKey(data); err != nil {
		if parsedKey, err = x509.ParsePKIXPublicKey(data); err != nil {
			return nil, err
		}
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errInvalidRSAPublicKeyData
	}

	return publicKey, nil
}

func ParseRSAPrivateKeyFromBase64(data string) (*rsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKeyFromBytes(bytes)
}

func ParseRSAPublicKeyFromBase64(data string) (*rsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKeyFromBytes(bytes)
}

func ParseRSAPrivateKeyFromPemBytes(data []byte) (*rsa.PrivateKey, error) {
	pemData, _ := pem.Decode(data)
	return ParseRSAPrivateKeyFromBytes(pemData.Bytes)
}

func ParseRSAPublicKeyFromPemBytes(data []byte) (*rsa.PublicKey, error) {
	pemData, _ := pem.Decode(data)
	return ParseRSAPublicKeyFromBytes(pemData.Bytes)
}

func ParseRSAPrivateKeyFromPemFile(filename string) (*rsa.PrivateKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKeyFromPemBytes(bytes)
}

func ParseRSAPublicKeyFromPemFile(filename string) (*rsa.PublicKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKeyFromPemBytes(bytes)
}
