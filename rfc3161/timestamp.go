package rfc3161

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
)

const (
	TsaFreeTsa  = "http://freetsa.org/tsr"
	TsaCertum   = "http://time.certum.pl"
	TsaComodora = "http://timestamp.comodoca.com/rfc3161"
)

func TimestampRequest(data []byte, url string) (*http.Request, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		url,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	req.Header.Set("Connection", "Close")
	req.Header.Set("Cache-Control", "no-cache")

	return req, nil
}

func TimestampResponse(data []byte, url string) (*http.Response, error) {
	req, err := TimestampRequest(data, url)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)

	return res, err
}

func Timestamp(data []byte, url string) (*string, error) {
	res, err := TimestampResponse(data, url)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(body)

	return &encoded, nil
}
