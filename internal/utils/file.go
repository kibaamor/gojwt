package utils

import (
	"os"
)

func WriteToTempFile(dir, pattern string, data []byte) (filename string, err error) {
	var f *os.File
	f, err = os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}

	_, err = f.Write(data)
	if err != nil {
		return "", err
	}

	filename = f.Name()

	err = f.Close()
	if err != nil {
		_ = os.Remove(f.Name())
	}

	return filename, err
}
