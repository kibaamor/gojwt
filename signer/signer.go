package signer

type Verifier interface {
	Id() string
	Name() string
	Verify(data, signature []byte) error
}

type Signer interface {
	Id() string
	Name() string
	Sign(data []byte) ([]byte, error)
	Verifier() Verifier
}
