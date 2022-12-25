//go:build test || unit

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			a := RandBytes(tt.input)
			b := RandBytes(tt.input)

			assert.Equal(t, tt.want, len(a))
			assert.Equal(t, tt.want, len(b))

			if tt.want > 0 {
				assert.NotEqual(t, a, b)
			}
		})
	}
}
