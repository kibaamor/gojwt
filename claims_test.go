package gojwt

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
	"time"
)

func TestClaims(t *testing.T) {
	c := NewClaims()

	str := "gojwt"
	c.SetString("str", str)
	strGot, err := c.GetString("str")
	assert.Nil(t, err)
	assert.Equal(t, str, strGot)

	strArr := []string{"gojwt", "kibaamor", "kibazen.cn"}
	c.SetStringArray("strArr", strArr)
	strArrGot, err := c.GetStringArray("strArr")
	assert.Nil(t, err)
	assert.Equal(t, strArr, strArrGot)

	i64Max := math.MaxInt64
	c.SetInteger("i64Max", i64Max)
	i64MaxGot, err := c.GetInteger("i64Max")
	assert.Nil(t, err)
	assert.Equal(t, i64Max, i64MaxGot)

	i64Min := math.MinInt64
	c.SetInteger("i64Min", i64Min)
	i64MinGot, err := c.GetInteger("i64Min")
	assert.Nil(t, err)
	assert.Equal(t, i64Min, i64MinGot)

	tm := time.Now()
	c.SetTime("tm", tm)
	tmGot, err := c.GetTime("tm")
	assert.Nil(t, err)
	assert.Equal(t, tm.Unix(), tmGot.Unix())
}
