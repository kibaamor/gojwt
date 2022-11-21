package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		padding int
		want    []byte
	}{
		{
			name:    "0 bytes",
			input:   []byte{},
			padding: 4,
			want:    []byte{4, 4, 4, 4},
		},
		{
			name:    "1 bytes",
			input:   []byte{8},
			padding: 4,
			want:    []byte{8, 3, 3, 3},
		},
		{
			name:    "2 bytes",
			input:   []byte{8, 8},
			padding: 4,
			want:    []byte{8, 8, 2, 2},
		},
		{
			name:    "3 bytes",
			input:   []byte{8, 8, 8},
			padding: 4,
			want:    []byte{8, 8, 8, 1},
		},
		{
			name:    "4 bytes",
			input:   []byte{8, 8, 8, 8},
			padding: 4,
			want:    []byte{8, 8, 8, 8, 4, 4, 4, 4},
		},
		{
			name:    "5 bytes",
			input:   []byte{8, 8, 8, 8, 8},
			padding: 4,
			want:    []byte{8, 8, 8, 8, 8, 3, 3, 3},
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS7Padding(tt.input, tt.padding)
			assert.Equal(t, tt.want, got)

			output, err := PKCS7Unpadding(got)
			assert.Nil(t, err)
			assert.Equal(t, tt.input, output)
		})
	}
}

func TestPKCS7Unpadding(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "nil input",
			input: nil,
		},
		{
			name:  "zero length",
			input: []byte{},
		},
		{
			name:  "invalid padding length",
			input: []byte{2},
		},
		{
			name:  "invalid padding values",
			input: []byte{1, 2},
		},
		{
			name:  "unequal padding values",
			input: []byte{8, 1, 2},
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PKCS7Unpadding(tt.input)
			if !assert.NotNil(t, err) {
				assert.Equal(t, errPKCS7Padding, err)
			}
		})
	}
}
