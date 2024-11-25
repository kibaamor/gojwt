package gojwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

var (
	errECDSAPrivateKeyData = errors.New("gojwt/ecdsautils: invalid ECDSA private key")
	errECDSAPublicKeyData  = errors.New("gojwt/ecdsautils: invalid ECDSA public key")
)

func ParseECDSAPrivateKeyFromBytes(data []byte) (*ecdsa.PrivateKey, error) {
	var (
		parsedKey any
		err       error
	)

	if parsedKey, err = x509.ParseECPrivateKey(data); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(data); err != nil {
			return nil, err
		}
	}

	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errECDSAPrivateKeyData
	}

	return privateKey, nil
}

func ParseECDSAPublicKeyFromBytes(data []byte) (*ecdsa.PublicKey, error) {
	var (
		parsedKey any
		err       error
	)

	if parsedKey, err = x509.ParsePKIXPublicKey(data); err != nil {
		return nil, err
	}

	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errECDSAPublicKeyData
	}

	return publicKey, nil
}

func ParseECDSAPrivateKeyFromBase64(data string) (*ecdsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return ParseECDSAPrivateKeyFromBytes(bytes)
}

func ParseECDSAPublicKeyFromBase64(data string) (*ecdsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return ParseECDSAPublicKeyFromBytes(bytes)
}

func ParseECDSAPrivateKeyFromPemBytes(data []byte) (*ecdsa.PrivateKey, error) {
	pemData, _ := pem.Decode(data)
	return ParseECDSAPrivateKeyFromBytes(pemData.Bytes)
}

func ParseECDSAPublicKeyFromPemBytes(data []byte) (*ecdsa.PublicKey, error) {
	pemData, _ := pem.Decode(data)
	return ParseECDSAPublicKeyFromBytes(pemData.Bytes)
}

func ParseECDSAPrivateKeyFromPemFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseECDSAPrivateKeyFromPemBytes(bytes)
}

func ParseECDSAPublicKeyFromPemFile(filename string) (*ecdsa.PublicKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseECDSAPublicKeyFromPemBytes(bytes)
}
