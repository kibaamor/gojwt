//go:build test || unit

package signer

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHMACSigner(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{
			id:   "hs256",
			name: "HS256",
		},
		{
			id:   "hs384",
			name: "HS384",
		},
		{
			id:   "hs384",
			name: "HS512",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := NewHMACSigner(tt.id, tt.name, []byte(tt.name))
			assert.Equal(t, tt.id, signer.ID())
			assert.Equal(t, tt.name, signer.Name())

			verifier := signer.Verifier()
			assert.Equal(t, tt.id, verifier.ID())
			assert.Equal(t, tt.name, verifier.Name())
		})
	}
}

func TestHMACSigner(t *testing.T) {
	tests := []struct {
		id   string
		name string
		data string
		want string
	}{
		{
			id:   "hs256",
			name: "HS256",
			data: "hs256",
			want: "W23aiRcWG+pdYz1qTslYF0Kx2uAjdG+Y5X6AaJiiCbY=",
		},
		{
			id:   "hs384",
			name: "HS384",
			data: "hs384",
			want: "Yni0yw25dY/6U2V07mJxBAID0Llw9g8mCOwa9Gk4W5K8Sepmsng3kxytK/w/gNr0",
		},
		{
			id:   "hs512",
			name: "HS512",
			data: "hs512",
			want: "BaXGQLYNqNpaWEMzFe8vsxBOCGuA3woz6Es1RjRbQFbfOh1AZ/zQhAVtWBkDgY5tX1rOZmamgX8fskhx9uTavA==",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := NewHMACSigner(tt.id, tt.name, []byte(tt.id))
			data := []byte(tt.data)

			sig, err := signer.Sign(data)
			assert.Nil(t, err)

			verifier := signer.Verifier()
			err = verifier.Verify(data, sig)
			assert.Nil(t, err)

			got := base64.StdEncoding.EncodeToString(sig)
			assert.Equal(t, tt.want, got)
		})
	}
}
