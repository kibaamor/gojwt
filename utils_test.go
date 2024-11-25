//go:build test || unit

package gojwt

import (
	"testing"

	"github.com/stretchr/testify/require"
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
			t.Parallel()
			require := require.New(t)

			got := PKCS7Padding(tt.input, tt.padding)
			require.Equal(tt.want, got)

			output, err := PKCS7Unpadding(got)
			require.NoError(err)
			require.Equal(tt.input, output)
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
			t.Parallel()
			require := require.New(t)

			_, err := PKCS7Unpadding(tt.input)
			require.Equal(errPKCS7Padding, err)
		})
	}
}

func TestRandBytes(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  int
	}{
		{
			name:  "negative length",
			input: -1,
			want:  0,
		},
		{
			name:  "zero length",
			input: 0,
			want:  0,
		},
		{
			name:  "positive length",
			input: 10,
			want:  10,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := require.New(t)

			a := RandBytes(tt.input)
			b := RandBytes(tt.input)

			require.Len(a, tt.want)
			require.Len(b, tt.want)

			if tt.want > 0 {
				require.NotEqual(a, b)
			}
		})
	}
}
