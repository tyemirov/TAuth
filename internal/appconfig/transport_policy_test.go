package appconfig

import (
	"net/http"
	"testing"
)

func TestTransportPolicyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, env                       string
		wantError, trustIPv4, trustIPv6 bool
	}{
		{"empty", "", false, false, false}, {"configured", "127.0.0.1/32, ::1/128", false, true, true},
		{"invalid", "localhost", true, false, false}, {"empty-element", "127.0.0.1/32,", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TAUTH_TRUSTED_PROXY_CIDRS", tc.env)
			config, err := ParseConfig([]byte("server:\n  trusted_proxy_cidrs: ['${TAUTH_TRUSTED_PROXY_CIDRS}']\n"))
			if (err != nil) != tc.wantError {
				t.Fatalf("error %v wantError %v", err, tc.wantError)
			}
			if err != nil {
				return
			}
			for _, peer := range []struct {
				addr string
				want bool
			}{{"127.0.0.1:80", tc.trustIPv4}, {"[::1]:80", tc.trustIPv6}} {
				request := &http.Request{RemoteAddr: peer.addr, Header: http.Header{"X-Forwarded-Proto": {"https"}}}
				if got := config.TransportPolicy().IsHTTPS(request); got != peer.want {
					t.Errorf("peer %s got %v want %v", peer.addr, got, peer.want)
				}
			}
		})
	}
}
