package transportsecurity_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tyemirov/tauth/internal/transportsecurity"
)

func TestPolicyHTTPTransport(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		var cidrs []string
		if trusted {
			cidrs = []string{"127.0.0.1/32", "::1/128"}
		}
		policy, err := transportsecurity.NewPolicy(cidrs)
		if err != nil {
			t.Fatal(err)
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !policy.IsHTTPS(r) {
				w.WriteHeader(400)
			}
		})
		plain := httptest.NewServer(handler)
		secure := httptest.NewTLSServer(handler)
		for _, tc := range []struct {
			name     string
			values   []string
			accepted bool
		}{
			{"absent", nil, false}, {"https", []string{"https"}, trusted}, {"duplicate", []string{"https", "https"}, false},
			{"comma", []string{"https,http"}, false}, {"mixed-case", []string{"HTTPS"}, false}, {"http", []string{"http"}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				for _, server := range []*httptest.Server{plain, secure} {
					req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
					req.Host = "localhost:8080"
					req.Header.Set("Forwarded", "proto=https")
					for _, value := range tc.values {
						req.Header.Add("X-Forwarded-Proto", value)
					}
					resp, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					resp.Body.Close()
					want := 400
					if tc.accepted || server == secure {
						want = 200
					}
					if resp.StatusCode != want {
						t.Fatalf("trusted=%v server=%s: status %d want %d", trusted, server.URL, resp.StatusCode, want)
					}
				}
			})
		}
		plain.Close()
		secure.Close()
	}
}

func TestPolicyAddressAndHeaderContract(t *testing.T) {
	policy, err := transportsecurity.NewPolicy([]string{"192.0.2.0/24", "2001:db8::/32", "::ffff:198.51.100.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		peer, value string
		want        bool
	}{
		{"192.0.2.1:80", "https", true}, {"[2001:db8::1]:80", "https", true}, {"[::ffff:192.0.2.1]:80", "https", true},
		{"[::ffff:198.51.100.1]:80", "https", true}, {"198.51.100.1:80", "https", true}, {"203.0.113.1:80", "https", false},
		{"192.0.2.1", "https", false}, {"bad", "https", false}, {"[fe80::1%lo0]:80", "https", false},
		{"192.0.2.1:80", " https", false}, {"192.0.2.1:80", "https ", false},
	} {
		req := &http.Request{RemoteAddr: tc.peer, Header: http.Header{"X-Forwarded-Proto": {tc.value}}}
		if got := policy.IsHTTPS(req); got != tc.want {
			t.Errorf("%q %q: got %v want %v", tc.peer, tc.value, got, tc.want)
		}
	}
	tls := &http.Request{TLS: &tls.ConnectionState{}, RemoteAddr: "bad"}
	if !policy.IsHTTPS(tls) {
		t.Fatal("TLS rejected")
	}
	for _, cidr := range []string{"", "localhost", "127.0.0.1", "127.0.0.1/33", "::ffff:0:0/80"} {
		if _, err := transportsecurity.NewPolicy([]string{cidr}); err == nil {
			t.Errorf("accepted invalid CIDR %q", cidr)
		}
	}
}
