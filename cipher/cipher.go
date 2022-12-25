package cipher

type Cipher interface {
	ID() string
	Name() string
	KeySize() int
	IVSize() int
	Encrypt(data, iv []byte) ([]byte, error)
	Decrypt(data, iv []byte) ([]byte, error)
}
