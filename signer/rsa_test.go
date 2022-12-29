//go:build test || unit

package signer

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kibaamor/gojwt/internal/test"
)

func TestNewRSASignerAndVerifier(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{
			id:   "rs256",
			name: "RS256",
		},
		{
			id:   "rs384",
			name: "RS384",
		},
		{
			id:   "rs512",
			name: "RS512",
		},
		{
			id:   "ps256",
			name: "PS256",
		},
		{
			id:   "ps384",
			name: "PS384",
		},
		{
			id:   "ps512",
			name: "PS512",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewRSASigner(tt.id, tt.name, test.RSAPrivateKey)
			assert.Nil(t, err)
			assert.Equal(t, tt.id, signer.ID())
			assert.Equal(t, tt.name, signer.Name())

			verifier := signer.Verifier()
			assert.Equal(t, tt.id, verifier.ID())
			assert.Equal(t, tt.name, verifier.Name())

			verifier, err = NewRSAVerifier(tt.id, tt.name, test.RSAPublicKey)
			assert.Nil(t, err)
			assert.Equal(t, tt.id, verifier.ID())
			assert.Equal(t, tt.name, verifier.Name())
		})
	}
}

func TestRSASignerAndVerifier(t *testing.T) {
	tests := []struct {
		id   string
		name string
		want string
	}{
		{
			id:   "rs256",
			name: "RS256",
			want: "fZUFFk0BD6DpudDJLN9PYk+SyYPz/QyWNdz+jsrD1dQtGOXzx4rsI7TlGQ8f5tUenc9HM8GKmN2bZAtkV55jtgxzj1RXDobpUgk9VQQkfuq1u9upIb9nOuprzIcRtGkTIc8SmtqBogN6Vl9QgtvsNOEDRqmd2f7AASI2hIaKvI9uLYReR6vQK4sBFfckcBNTdW2oQvMZoERqfC6lWb760ZbE6Ww2HJ8l6XuA7SRJD6iivwxKq7XyI7JOB57SFyz5N7osoO4qAWh0lalqiqkqwWykovg4TbHKzF5+EM4AyuIDqgB+CuBlDwwp/l2UevxGuDgxIZA+ns3t5bp3F+eifw==",
		},
		{
			id:   "rs384",
			name: "RS384",
			want: "FvNAHCrGhD0/JVVujRUzcFE90LkQYzHedp9ppyKGv1ZaAxfbPVTiG/zf/9Z7PZHyfUNlpNS/msnpLan4ThVoWnsNx3jTXHabJPA9EYzKXzGIKxAknU+U/OgRMph1ZlOTIbEc4T1gn4vJXM3otqBo3ZAv+kk4RcPY327PrXltwzckWPyFkwop0CQfthkN+okE3jKrMth961ybuDoSx5PDCrT4lqJ/NCUdBp2uhouT6ShhcLzDSS0jU6pftLOjJtyTmQ9+LiUoXQAG40XPa+mtdC/mjGy9miC3gKwSsLWrtck3OB5ZiSXWLsXvMaDENlPUxzrjqgJyP8KWLQ7OhqmMbg==",
		},
		{
			id:   "rs512",
			name: "RS512",
			want: "k8xE9rJIrFt4pG6uYhWmC+KZ3gxZd3g5WjdNw3pizOaBWE/jAAlQpLxyigAlkLZHqJ3Y8QK3xiVM+G373Uyj4Iaz+Ugi+Qc31E0tdCc7CL8HANgqCliY/Zfd/RMG0cTkWPOPLeHZHvtoBN0hzr9gQGvjEWPksLC0GsohbgHzY2BHnaomletMS9EFETlq3BWruIiwnJeKbiVpd0QnLYrT8cR9++cfL+a3ARRc5JhfCmXnj9KVwb+FxO/8arJLDxZUTAYHwse0Qu9dtD2iXymzHFi/qjQ4Kmz1LYV4nCPj6KnS1XNz2Uic43X34hKonqeVIImF02HeMQw99jHRES41EA==",
		},
		{
			id:   "ps256",
			name: "PS256",
			want: "",
		},
		{
			id:   "ps384",
			name: "PS384",
			want: "",
		},
		{
			id:   "ps512",
			name: "PS512",
			want: "",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewRSASigner(tt.id, tt.name, test.RSAPrivateKey)
			assert.Nil(t, err)

			data := []byte(tt.name)

			sig, err := signer.Sign(data)
			assert.Nil(t, err)

			verifier, err := NewRSAVerifier(tt.id, tt.name, test.RSAPublicKey)
			assert.Nil(t, err)
			err = verifier.Verify(data, sig)
			assert.Nil(t, err)

			verifier = signer.Verifier()
			err = verifier.Verify(data, sig)
			assert.Nil(t, err)

			if len(tt.want) > 0 {
				got := base64.StdEncoding.EncodeToString(sig)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
