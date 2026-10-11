// Package transportsecurity classifies transport from TLS and explicitly trusted proxy peers.
package transportsecurity

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

var hostnameLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Resolver supplies current addresses for explicitly trusted proxy hostnames.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// ProxyConfig declares explicit static ranges and dynamically resolved proxy hosts.
type ProxyConfig struct {
	CIDRs         []string
	Hosts         []string
	LookupTimeout time.Duration
}

// Policy is an immutable transport policy. Its zero value trusts no proxy peers.
type Policy struct {
	trusted       []netip.Prefix
	hosts         []string
	lookupTimeout time.Duration
	resolver      Resolver
}

// NewPolicy validates proxy ranges, hostnames, and resolution policy at the configuration boundary.
func NewPolicy(config ProxyConfig, resolver Resolver) (Policy, error) {
	prefixes := make([]netip.Prefix, 0, len(config.CIDRs))
	for _, cidr := range config.CIDRs {
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
	hosts := make([]string, 0, len(config.Hosts))
	for _, hostname := range config.Hosts {
		hostname = strings.ToLower(hostname)
		if len(hostname) == 0 || len(hostname) > 253 {
			return Policy{}, fmt.Errorf("transportsecurity.trusted_proxy_host %q: invalid hostname length", hostname)
		}
		if _, err := netip.ParseAddr(hostname); err == nil {
			return Policy{}, fmt.Errorf("transportsecurity.trusted_proxy_host %q: IP literals must use CIDRs", hostname)
		}
		for _, label := range strings.Split(hostname, ".") {
			if !hostnameLabelPattern.MatchString(label) {
				return Policy{}, fmt.Errorf("transportsecurity.trusted_proxy_host %q: invalid hostname label", hostname)
			}
		}
		hosts = append(hosts, hostname)
	}
	if len(hosts) > 0 && (config.LookupTimeout <= 0 || resolver == nil) {
		return Policy{}, fmt.Errorf("transportsecurity.trusted_proxy_lookup: proxy hosts require a resolver and positive lookup timeout")
	}
	return Policy{trusted: prefixes, hosts: hosts, lookupTimeout: config.LookupTimeout, resolver: resolver}, nil
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
	if len(policy.hosts) == 0 {
		return false
	}
	lookupContext, cancel := context.WithTimeout(request.Context(), policy.lookupTimeout)
	defer cancel()
	for _, hostname := range policy.hosts {
		addresses, err := policy.resolver.LookupNetIP(lookupContext, "ip", hostname)
		if err == nil {
			err = lookupContext.Err()
		}
		if err != nil {
			slog.ErrorContext(request.Context(), "transportsecurity.proxy_resolution_failed", "hostname", hostname, "error", fmt.Errorf("resolve trusted proxy %s: %w", hostname, err))
			return false
		}
		if len(addresses) == 0 {
			slog.ErrorContext(request.Context(), "transportsecurity.proxy_resolution_empty", "hostname", hostname)
			return false
		}
		for _, address := range addresses {
			if address.Unmap() == peer {
				return true
			}
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
