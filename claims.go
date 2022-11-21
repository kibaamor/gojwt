package gojwt

import (
	"encoding/json"
	"fmt"
	"time"
)

type Claims map[string]interface{}

func NewClaims() Claims {
	return make(Claims)
}

func (c Claims) String() string {
	js, _ := json.Marshal(c)
	return string(js)
}

func (c Claims) set(key string, value interface{}) {
	c[key] = value
}

func (c Claims) SetString(key, value string) {
	c.set(key, value)
}

func (c Claims) SetStringArray(key string, value []string) {
	c.set(key, value)
}

func (c Claims) SetInteger(key string, value int) {
	c.set(key, value)
}

func (c Claims) SetTime(key string, tm time.Time) {
	c.SetInteger(key, int(tm.Unix()))
}

func (c Claims) get(key string) (interface{}, error) {
	v, ok := c[key]
	if !ok {
		return nil, fmt.Errorf("claims: key '%v' does not exists", key)
	}
	return v, nil
}

func (c Claims) GetString(key string) (string, error) {
	val, err := c.get(key)
	if err != nil {
		return "", err
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("claims: the value of key '%v' is not a string", key)
	}
	return str, nil
}

func (c Claims) GetStringArray(key string) ([]string, error) {
	val, err := c.get(key)
	if err != nil {
		return nil, err
	}

	arr, ok := val.([]string)
	if !ok {
		return nil, fmt.Errorf("claims: the value of key '%v' is not a string", key)
	}
	return arr, nil
}

func (c Claims) GetInteger(key string) (int, error) {
	val, err := c.get(key)
	if err != nil {
		return 0, err
	}

	i, ok := val.(int)
	if !ok {
		return 0, fmt.Errorf("claims: the value of key '%v' is not a integer", key)
	}
	return i, nil
}

func (c Claims) GetTime(key string) (t time.Time, err error) {
	var i int
	i, err = c.GetInteger(key)
	if err != nil {
		return
	}

	t = time.Unix(int64(i), 0)
	return
}
