package cipher

type Cipher interface {
	Id() string
	Name() string
	KeySize() int
	IVSize() int
	Encrypt(data, iv []byte) ([]byte, error)
	Decrypt(data, iv []byte) ([]byte, error)
}
