package utils

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"

	"github.com/andybalholm/brotli"
)

func CompressAndBase64Encode(input []byte) (string, error) {
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	_, err := writer.Write(input)
	if err != nil {
		return "", err
	}
	writer.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func DecompressAndBase64Decode(input string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	reader := brotli.NewReader(bytes.NewReader(decoded))
	decompressed, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}
