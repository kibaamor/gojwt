package test

import (
	"crypto/ecdsa"
	"github.com/kibaamor/gojwt/util"
)

var (
	ECDSAP256PrivateKey *ecdsa.PrivateKey
	ECDSAP256PublicKey  *ecdsa.PublicKey
	ECDSAP384PrivateKey *ecdsa.PrivateKey
	ECDSAP384PublicKey  *ecdsa.PublicKey
	ECDSAP521PrivateKey *ecdsa.PrivateKey
	ECDSAP521PublicKey  *ecdsa.PublicKey
)

// openssl ecparam -name prime256v1 -genkey -noout -out p256pri.pem
// openssl ec -in p256pri.pem -pubout -out p256pub.pem
//
// openssl ecparam -name secp384r1 -genkey -noout -out p384pri.pem
// openssl ec -in p384pri.pem -pubout -out p384pub.pem
//
// openssl ecparam -name secp521r1 -genkey -noout -out p521pri.pem
// openssl ec -in p521pri.pem -pubout -out p521pub.pem

func init() {
	p256privateKey := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJm67wsGJQKGxLOKSFNVE0pBsxTR1GJtFsXctjyZ+FxzoAoGCCqGSM49
AwEHoUQDQgAECvmf+/qb8J8FTl9q18WyIMTiCOUAUmkfuRXsKkdyLPtKOgJU2VZT
489td4R0WLRUC1FwxRy8e7N3t2cLh7rlAw==
-----END EC PRIVATE KEY-----
`
	p256publicKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECvmf+/qb8J8FTl9q18WyIMTiCOUA
UmkfuRXsKkdyLPtKOgJU2VZT489td4R0WLRUC1FwxRy8e7N3t2cLh7rlAw==
-----END PUBLIC KEY-----
`

	p384privateKey := `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBmx0VxL1k8YZfqvlGOQ8M0FeRhMWydzqLAUoDCRoZMQfHhCHLy9dx1
E8UJ254a97igBwYFK4EEACKhZANiAASzPewigZF04aqLLS/yw3Lk8pwVFhzCkcwA
1+FRaZezsnHkYlVqi8pPLsnC8gf2vgYPF+4eLwc4S502wphtc4NgnCjWivdOpksZ
cBrHLfh9W4mm9Ly1aRsvPOSmOUcexxo=
-----END EC PRIVATE KEY-----
`
	p384publicKey := `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsz3sIoGRdOGqiy0v8sNy5PKcFRYcwpHM
ANfhUWmXs7Jx5GJVaovKTy7JwvIH9r4GDxfuHi8HOEudNsKYbXODYJwo1or3TqZL
GXAaxy34fVuJpvS8tWkbLzzkpjlHHsca
-----END PUBLIC KEY-----
`

	p521privateKey := `
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIATGeKcYim0p840ETmuj7F/vpUyc+Fa5nu2ZfNVyv+3aIIwxvDb1Rx
2Y3/AdFMZvoQaEcNwahKVZZkBuXRcctVaAWgBwYFK4EEACOhgYkDgYYABACCWUR2
nkYmHKoLJDda0O3LZ4h422QCw9NmkWbIBsOB7dFhkd4lGaRfMVJr/m0IesmZ40YP
DbQPcYeiFKixMVE3+QAJxclP8cGIFQr9og0Fg2w5dT64DzbPb0Uu+ZiJGxQAADja
2ZqAtIrIgxR1t3Q4BQzyKSCxysFapn9eSX218XFrBA==
-----END EC PRIVATE KEY-----
`
	p521publicKey := `
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAgllEdp5GJhyqCyQ3WtDty2eIeNtk
AsPTZpFmyAbDge3RYZHeJRmkXzFSa/5tCHrJmeNGDw20D3GHohSosTFRN/kACcXJ
T/HBiBUK/aINBYNsOXU+uA82z29FLvmYiRsUAAA42tmagLSKyIMUdbd0OAUM8ikg
scrBWqZ/Xkl9tfFxawQ=
-----END PUBLIC KEY-----
`

	parsePri := func(s string) *ecdsa.PrivateKey {
		pri, err := util.ParseECDSAPrivateKeyFromPemBytes([]byte(s))
		if err != nil {
			panic(err)
		}
		return pri
	}
	parsePub := func(s string) *ecdsa.PublicKey {
		pub, err := util.ParseECDSAPublicKeyFromPemBytes([]byte(s))
		if err != nil {
			panic(err)
		}
		return pub
	}

	ECDSAP256PrivateKey = parsePri(p256privateKey)
	ECDSAP256PublicKey = parsePub(p256publicKey)
	ECDSAP384PrivateKey = parsePri(p384privateKey)
	ECDSAP384PublicKey = parsePub(p384publicKey)
	ECDSAP521PrivateKey = parsePri(p521privateKey)
	ECDSAP521PublicKey = parsePub(p521publicKey)

	match := func(pri *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
		if !pri.PublicKey.Equal(pub) {
			panic("test/ecdsa: public and private are mismatch")
		}
	}
	match(ECDSAP256PrivateKey, ECDSAP256PublicKey)
	match(ECDSAP384PrivateKey, ECDSAP384PublicKey)
	match(ECDSAP521PrivateKey, ECDSAP521PublicKey)
}
