package transportsecurity_test

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/tyemirov/tauth/internal/transportsecurity"
)

type hostnameResolver struct{ addresses []netip.Addr }

func (resolver *hostnameResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return resolver.addresses, nil
}

func TestPolicyProxyHostReplacement(t *testing.T) {
	resolver := &hostnameResolver{}
	policy, err := transportsecurity.NewPolicy(transportsecurity.ProxyConfig{Hosts: []string{"proxy.internal"}, LookupTimeout: time.Second}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	for _, addresses := range [][]netip.Addr{
		{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
		{netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("2001:db8::11")},
	} {
		resolver.addresses = addresses
		for _, raw := range []string{"192.0.2.10", "192.0.2.11", "2001:db8::10", "2001:db8::11", "::ffff:192.0.2.10", "::ffff:192.0.2.11", "203.0.113.1"} {
			address := netip.MustParseAddr(raw)
			request := &http.Request{RemoteAddr: netip.AddrPortFrom(address, 12345).String(), Header: http.Header{"X-Forwarded-Proto": {"https"}}}
			want := address.Unmap() == addresses[0] || address == addresses[1]
			if got := policy.IsHTTPS(request); got != want {
				t.Errorf("current=%v peer=%s got=%v want=%v", addresses, address, got, want)
			}
		}
	}
}

func TestPolicyProxyHostValidation(t *testing.T) {
	resolver := &hostnameResolver{}
	for _, hostname := range []string{"", "127.0.0.1", "::1", "https://proxy.internal", "proxy:8080", "-proxy", "proxy-", "proxy..internal", "proxy internal"} {
		if _, err := transportsecurity.NewPolicy(transportsecurity.ProxyConfig{Hosts: []string{hostname}, LookupTimeout: time.Second}, resolver); err == nil {
			t.Errorf("accepted hostname %q", hostname)
		}
	}
	for _, timeout := range []time.Duration{0, -time.Second} {
		if _, err := transportsecurity.NewPolicy(transportsecurity.ProxyConfig{Hosts: []string{"proxy.internal"}, LookupTimeout: timeout}, resolver); err == nil {
			t.Errorf("accepted timeout %s", timeout)
		}
	}
	if _, err := transportsecurity.NewPolicy(transportsecurity.ProxyConfig{Hosts: []string{"proxy.internal"}, LookupTimeout: time.Second}, nil); err == nil {
		t.Fatal("accepted missing resolver")
	}
}
