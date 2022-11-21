package test

import (
	"crypto/rsa"
	"github.com/kibaamor/gojwt/util"
)

var (
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
)

func init() {
	// https://8gwifi.org/RSAFunctionality?rsasignverifyfunctions=rsasignverifyfunctions&keysize=1024

	pri := `
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
	pub := `
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

	var err error
	RSAPrivateKey, err = util.ParseRSAPrivateKeyFromPemBytes([]byte(pri))
	if err != nil {
		panic(err)
	}
	RSAPublicKey, err = util.ParseRSAPublicKeyFromPemBytes([]byte(pub))
	if err != nil {
		panic(err)
	}
	if !RSAPublicKey.Equal(&RSAPrivateKey.PublicKey) {
		panic("test: RSAPrivateKey and RSAPublicKey are mismatch")
	}
}
