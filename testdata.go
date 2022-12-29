//go:build test || unit

package gojwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

var (
	rsaPrivateKeyForTest       *rsa.PrivateKey
	rsaPublicKeyForTest        *rsa.PublicKey
	ecdsaP256PrivateKeyForTest *ecdsa.PrivateKey
	ecdsaP256PublicKeyForTest  *ecdsa.PublicKey
	ecdsaP384PrivateKeyForTest *ecdsa.PrivateKey
	ecdsaP384PublicKeyForTest  *ecdsa.PublicKey
	ecdsaP521PrivateKeyForTest *ecdsa.PrivateKey
	ecdsaP521PublicKeyForTest  *ecdsa.PublicKey
)

// https://8gwifi.org/RSAFunctionality?rsasignverifyfunctions=rsasignverifyfunctions&keysize=1024
//
// openssl ecparam -name prime256v1 -genkey -noout -out p256pri.pem
// openssl ec -in p256pri.pem -pubout -out p256pub.pem
//
// openssl ecparam -name secp384r1 -genkey -noout -out p384pri.pem
// openssl ec -in p384pri.pem -pubout -out p384pub.pem
//
// openssl ecparam -name secp521r1 -genkey -noout -out p521pri.pem
// openssl ec -in p521pri.pem -pubout -out p521pub.pem

func init() {
	rsaPrivateKey := `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAlLWg896tlxOT3cbNbcIGz4JuZxT6zzVW6/r3S6Uzai2xIgeq
C+CfHlOhlbtBaqaW84RbYvAxK/VdyNyD0DGFl//Od6eewrfkwHHwCpwG6hWUDQdV
XvAiHd3hF8k25kRM4L9zRQXUBpvJJswFR2Xiov+EJ0ZG9Bo3fk2L51uT7Ly/YTDl
0pc38qkoYKliRAm+FZHg1J9lBHOb9RblP0HkFrRO/y/E1fAX6+ia5hsrrckM3oVR
TVJuVnwTFX/3ygaC17abd8+f/ZYO6p6wLL6uxmOvLKImyzi8sshy3mb0WTN1nr7J
/rd0A5wfR5HtmiOyWfSey887d9eImRe0ZKAy4wIDAQABAoIBACe77BidLBbM5VqB
rwwfpsA1Yphqc6V/5AzDjuYIaxd4w/aKw7XOu9VXlTozwYPkpTrF58Ek2o6bTgbI
XPP493AoqpswD2yJxDZjezbqf7J2N4vPpNDsKsF+MpGvctrN7xiyLvOHXiKx52pV
Yyezon3Y9g+kaHr6sk8uGy6jOoAree8bCR++xdUA1g9vVr+fDYkNaHPs8Gvr3w3K
6+LKeYsPIQn22S2gbHZCGs9MqlQ011ssa/Tk7FBDPp8hnV13fRLs0W39163K6gvT
7e1MF7e8EUsmpKEBwPoN4NyznJJlSY9hOtaN+TcVn1da0WVT+AUs8/iWWA1vOUJ8
d4jHOXkCgYEA1RXTLumKXO62vzSJwSXW1uksk7ko7mkzI7vF7HN/2oefuMR2F16g
kzuxg4KqzrxWoeGMoTPYSn92dH4e5TrcygwF6Rb08g/1kFxx5HiSLhIuuXi1guQj
OGo/y7hSGQL8lpSfbym4usqEG5/AsuhizzzEAqSpg7PV+6YxjI+jHh0CgYEAsqi9
kgdjDr34AlXt3MBB8a7nXMn7swQKDoBd6iqHtzq3fTqYaprMNKqfT9txRl9pVMB6
zGmjDn4vuZo5/NVpR25RW84dkWHE7Z9h4d0Modz7xLIKFj74Xa0lgWhb2++h14ex
ASjtedydLQ7Wd3cJZOrbEd/5v3zocF9GyhbDxP8CgYBf+9nKCvcBj6IQFQlsULAq
1JP44vIWGpsnoICyVwCjnm4LG6waMMziJYR7udNZFqtrdh8TyjfGrw3bwagHF/G2
rZ3H9khV9WxnH81J3inyyMv1TfNtR3i6A9pC2P9aNucyqTX8K+4Dbg/+JYL21AkW
Usf0bNnS8qIUHjO5nkYa3QKBgQCco/2xrvBW2JA93AE07wviTqtjW2RnTD9U/49X
4/oh2EVQcrN3pEkuU/piFdB3FuhO+oOv/V6NMm29mU8GMkaf7kU+7LRX5xS2EmvL
j/enYw0LI95cKtGvsEOV9l2zs6J+SeYTUkMD+T2FZ+D51VBTPubcATgDgAx7mc2D
GfqDGQKBgQDNkiC2VIHvD4t9+Mqv2kd6uHYWb4smSGPzpbKRGXHPL4Kh9z+FVmVe
D9SUgxnzD23D6NLHGbPJmPyuqbgEiMuGUWvA3r79JDKmamDlqb2/VtT4/pgQ4dzB
r8VyWXxQ+eHj5rCgZ+sp2BG3q0hFmuwZkt2oniO8MlOUsAv9znw6Hw==
-----END RSA PRIVATE KEY-----
`
	rsaPublicKey := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlLWg896tlxOT3cbNbcIG
z4JuZxT6zzVW6/r3S6Uzai2xIgeqC+CfHlOhlbtBaqaW84RbYvAxK/VdyNyD0DGF
l//Od6eewrfkwHHwCpwG6hWUDQdVXvAiHd3hF8k25kRM4L9zRQXUBpvJJswFR2Xi
ov+EJ0ZG9Bo3fk2L51uT7Ly/YTDl0pc38qkoYKliRAm+FZHg1J9lBHOb9RblP0Hk
FrRO/y/E1fAX6+ia5hsrrckM3oVRTVJuVnwTFX/3ygaC17abd8+f/ZYO6p6wLL6u
xmOvLKImyzi8sshy3mb0WTN1nr7J/rd0A5wfR5HtmiOyWfSey887d9eImRe0ZKAy
4wIDAQAB
-----END PUBLIC KEY-----
`

	p256PrivateKey := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJm67wsGJQKGxLOKSFNVE0pBsxTR1GJtFsXctjyZ+FxzoAoGCCqGSM49
AwEHoUQDQgAECvmf+/qb8J8FTl9q18WyIMTiCOUAUmkfuRXsKkdyLPtKOgJU2VZT
489td4R0WLRUC1FwxRy8e7N3t2cLh7rlAw==
-----END EC PRIVATE KEY-----
`
	p256PublicKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECvmf+/qb8J8FTl9q18WyIMTiCOUA
UmkfuRXsKkdyLPtKOgJU2VZT489td4R0WLRUC1FwxRy8e7N3t2cLh7rlAw==
-----END PUBLIC KEY-----
`

	p384PrivateKey := `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBmx0VxL1k8YZfqvlGOQ8M0FeRhMWydzqLAUoDCRoZMQfHhCHLy9dx1
E8UJ254a97igBwYFK4EEACKhZANiAASzPewigZF04aqLLS/yw3Lk8pwVFhzCkcwA
1+FRaZezsnHkYlVqi8pPLsnC8gf2vgYPF+4eLwc4S502wphtc4NgnCjWivdOpksZ
cBrHLfh9W4mm9Ly1aRsvPOSmOUcexxo=
-----END EC PRIVATE KEY-----
`
	p384PublicKey := `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsz3sIoGRdOGqiy0v8sNy5PKcFRYcwpHM
ANfhUWmXs7Jx5GJVaovKTy7JwvIH9r4GDxfuHi8HOEudNsKYbXODYJwo1or3TqZL
GXAaxy34fVuJpvS8tWkbLzzkpjlHHsca
-----END PUBLIC KEY-----
`

	p521PrivateKey := `
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIATGeKcYim0p840ETmuj7F/vpUyc+Fa5nu2ZfNVyv+3aIIwxvDb1Rx
2Y3/AdFMZvoQaEcNwahKVZZkBuXRcctVaAWgBwYFK4EEACOhgYkDgYYABACCWUR2
nkYmHKoLJDda0O3LZ4h422QCw9NmkWbIBsOB7dFhkd4lGaRfMVJr/m0IesmZ40YP
DbQPcYeiFKixMVE3+QAJxclP8cGIFQr9og0Fg2w5dT64DzbPb0Uu+ZiJGxQAADja
2ZqAtIrIgxR1t3Q4BQzyKSCxysFapn9eSX218XFrBA==
-----END EC PRIVATE KEY-----
`
	p521PublicKey := `
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAgllEdp5GJhyqCyQ3WtDty2eIeNtk
AsPTZpFmyAbDge3RYZHeJRmkXzFSa/5tCHrJmeNGDw20D3GHohSosTFRN/kACcXJ
T/HBiBUK/aINBYNsOXU+uA82z29FLvmYiRsUAAA42tmagLSKyIMUdbd0OAUM8ikg
scrBWqZ/Xkl9tfFxawQ=
-----END PUBLIC KEY-----
`

	var err error
	rsaPrivateKeyForTest, err = ParseRSAPrivateKeyFromPemBytes([]byte(rsaPrivateKey))
	if err != nil {
		panic(err)
	}
	rsaPublicKeyForTest, err = ParseRSAPublicKeyFromPemBytes([]byte(rsaPublicKey))
	if err != nil {
		panic(err)
	}
	if !rsaPublicKeyForTest.Equal(&rsaPrivateKeyForTest.PublicKey) {
		panic("testdata: rsaPrivateKeyForTest and rsaPublicKeyForTest are mismatch")
	}

	parseECDSAPrivateKey := func(s string) *ecdsa.PrivateKey {
		pri, err := ParseECDSAPrivateKeyFromPemBytes([]byte(s))
		if err != nil {
			panic(err)
		}
		return pri
	}
	parseECDSAPublicKey := func(s string) *ecdsa.PublicKey {
		pub, err := ParseECDSAPublicKeyFromPemBytes([]byte(s))
		if err != nil {
			panic(err)
		}
		return pub
	}

	ecdsaP256PrivateKeyForTest = parseECDSAPrivateKey(p256PrivateKey)
	ecdsaP256PublicKeyForTest = parseECDSAPublicKey(p256PublicKey)
	ecdsaP384PrivateKeyForTest = parseECDSAPrivateKey(p384PrivateKey)
	ecdsaP384PublicKeyForTest = parseECDSAPublicKey(p384PublicKey)
	ecdsaP521PrivateKeyForTest = parseECDSAPrivateKey(p521PrivateKey)
	ecdsaP521PublicKeyForTest = parseECDSAPublicKey(p521PublicKey)

	match := func(pri *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
		if !pri.PublicKey.Equal(pub) {
			panic("testdata/ecdsa: public and private are mismatch")
		}
	}
	match(ecdsaP256PrivateKeyForTest, ecdsaP256PublicKeyForTest)
	match(ecdsaP384PrivateKeyForTest, ecdsaP384PublicKeyForTest)
	match(ecdsaP521PrivateKeyForTest, ecdsaP521PublicKeyForTest)
}
