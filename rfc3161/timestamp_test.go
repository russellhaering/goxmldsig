package rfc3161

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
)

func TestTimestampResponse(t *testing.T) {
	type args struct {
		data []byte
		url  string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{"Empty", args{[]byte(""), TsaFreeTsa}, 200, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TimestampResponse(tt.args.data, tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("TimestampResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.StatusCode != tt.want {
				t.Errorf("TimestampResponse() = %v, want %v", got, tt.want)
			}
			body, err := ioutil.ReadAll(got.Body)
			if tt.want == 200 && err != nil {
				t.Error(err)
			} else if tt.want == 200 {
				t.Error(base64.StdEncoding.EncodeToString(body))
			}
		})
	}
}
