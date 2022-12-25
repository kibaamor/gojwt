package claims

type HeaderInterface interface {
	GetAlgorithm() string
	SetAlgorithm(string)
	GetEncryption() string
	SetEncryption(string)
	GetType() string
	SetType(string)
	GetSignerID() string
	SetSignerID(string)
	GetCipherID() string
	SetCipherID(string)
	GetIV() string
	SetIV(string)
}

type BasicHeader struct {
	Algorithm  string `json:"alg,omitempty"`
	Encryption string `json:"enc,omitempty"`
	Type       string `json:"typ,omitempty"`
	SignerID   string `json:"sid,omitempty"`
	CipherID   string `json:"cid,omitempty"`
	IV         string `json:"iv,omitempty"`
}

func (h *BasicHeader) GetAlgorithm() string {
	return h.Algorithm
}

func (h *BasicHeader) SetAlgorithm(s string) {
	h.Algorithm = s
}

func (h *BasicHeader) GetEncryption() string {
	return h.Encryption
}

func (h *BasicHeader) SetEncryption(s string) {
	h.Encryption = s
}

func (h *BasicHeader) GetType() string {
	return h.Type
}

func (h *BasicHeader) SetType(s string) {
	h.Type = s
}

func (h *BasicHeader) GetSignerID() string {
	return h.SignerID
}

func (h *BasicHeader) SetSignerID(s string) {
	h.SignerID = s
}

func (h *BasicHeader) GetCipherID() string {
	return h.CipherID
}

func (h *BasicHeader) SetCipherID(s string) {
	h.CipherID = s
}

func (h *BasicHeader) GetIV() string {
	return h.IV
}

func (h *BasicHeader) SetIV(s string) {
	h.IV = s
}
