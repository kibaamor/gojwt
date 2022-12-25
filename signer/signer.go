package signer

type Verifier interface {
	ID() string
	Name() string
	Verify(data, signature []byte) error
}

type Signer interface {
	ID() string
	Name() string
	Sign(data []byte) ([]byte, error)
	Verifier() Verifier
}
