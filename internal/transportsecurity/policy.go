// Package transportsecurity classifies transport from TLS and explicitly trusted proxy peers.
package transportsecurity

import (
	"fmt"
	"net/http"
	"net/netip"
)

// Policy is an immutable transport policy. Its zero value trusts no proxy peers.
type Policy struct{ trusted []netip.Prefix }

// NewPolicy validates the configured proxy CIDRs at the configuration boundary.
func NewPolicy(cidrs []string) (Policy, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return Policy{}, fmt.Errorf("transportsecurity.trusted_proxy_cidr %q: %w", cidr, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return Policy{}, fmt.Errorf("transportsecurity.trusted_proxy_cidr %q: mapped prefix must contain only mapped IPv4 addresses", cidr)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return Policy{trusted: prefixes}, nil
}

// IsHTTPS accepts TLS independently of headers. Plaintext requires an actual
// trusted RemoteAddr peer and exactly one lowercase X-Forwarded-Proto https value.
// Forwarded and Host do not supply transport evidence. Mapped IPv4 peers are
// normalized to IPv4; zone-qualified and malformed peers are rejected.
func (policy Policy) IsHTTPS(request *http.Request) bool {
	if request.TLS != nil {
		return true
	}
	peer, ok := peerAddress(request)
	if !ok {
		return false
	}
	values := request.Header.Values("X-Forwarded-Proto")
	if len(values) != 1 || values[0] != "https" {
		return false
	}
	for _, prefix := range policy.trusted {
		if prefix.Contains(peer) {
			return true
		}
	}
	return false
}

// IsLoopbackPeer identifies a direct loopback connection from RemoteAddr.
func (policy Policy) IsLoopbackPeer(request *http.Request) bool {
	peer, ok := peerAddress(request)
	return ok && peer.IsLoopback()
}

func peerAddress(request *http.Request) (netip.Addr, bool) {
	peer, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil || peer.Addr().Zone() != "" {
		return netip.Addr{}, false
	}
	return peer.Addr().Unmap(), true
}
