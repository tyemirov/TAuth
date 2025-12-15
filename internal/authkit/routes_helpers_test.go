package authkit

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/api/idtoken"
)

type noopGoogleTokenValidator struct{}

func (noopGoogleTokenValidator) Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
	return &idtoken.Payload{}, nil
}

func TestResolveGoogleValidatorCachesInstance(t *testing.T) {
	ProvideGoogleTokenValidator(nil)

	callCount := 0
	originalBuilder := newGoogleTokenValidator
	newGoogleTokenValidator = func(ctx context.Context) (GoogleTokenValidator, error) {
		callCount++
		return noopGoogleTokenValidator{}, nil
	}
	defer func() {
		newGoogleTokenValidator = originalBuilder
		ProvideGoogleTokenValidator(nil)
	}()

	first, firstErr := resolveGoogleValidator(context.Background())
	if firstErr != nil {
		t.Fatalf("expected first resolve to succeed: %v", firstErr)
	}
	if first == nil {
		t.Fatalf("expected validator")
	}

	second, secondErr := resolveGoogleValidator(context.Background())
	if secondErr != nil {
		t.Fatalf("expected second resolve to succeed: %v", secondErr)
	}
	if second == nil {
		t.Fatalf("expected cached validator")
	}

	if callCount != 1 {
		t.Fatalf("expected builder to be called once, got %d", callCount)
	}
}

func TestResolveGoogleValidatorReturnsConfiguredValidator(t *testing.T) {
	ProvideGoogleTokenValidator(noopGoogleTokenValidator{})
	defer ProvideGoogleTokenValidator(nil)

	validator, err := resolveGoogleValidator(context.Background())
	if err != nil {
		t.Fatalf("expected resolve to succeed: %v", err)
	}
	if validator == nil {
		t.Fatalf("expected validator")
	}
}

func TestResolveGoogleValidatorForwardsBuilderError(t *testing.T) {
	ProvideGoogleTokenValidator(nil)

	originalBuilder := newGoogleTokenValidator
	newGoogleTokenValidator = func(ctx context.Context) (GoogleTokenValidator, error) {
		return nil, errors.New("validator.build.failed")
	}
	defer func() {
		newGoogleTokenValidator = originalBuilder
		ProvideGoogleTokenValidator(nil)
	}()

	if _, err := resolveGoogleValidator(context.Background()); err == nil {
		t.Fatalf("expected resolve to fail")
	}
}

func TestIsHTTPSDetectsSignals(t *testing.T) {
	testCases := []struct {
		name     string
		request  *http.Request
		expected bool
	}{
		{
			name:     "tls_present",
			request:  &http.Request{TLS: &tls.ConnectionState{}},
			expected: true,
		},
		{
			name: "x_forwarded_proto",
			request: func() *http.Request {
				req := &http.Request{Header: make(http.Header)}
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			}(),
			expected: true,
		},
		{
			name: "forwarded_proto",
			request: func() *http.Request {
				req := &http.Request{Header: make(http.Header)}
				req.Header.Set("Forwarded", "for=192.0.2.1;proto=https")
				return req
			}(),
			expected: true,
		},
		{
			name:     "localhost_with_port",
			request:  &http.Request{Host: "localhost:8080"},
			expected: true,
		},
		{
			name:     "plain_http",
			request:  &http.Request{Host: "example.com"},
			expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := isHTTPS(testCase.request); got != testCase.expected {
				t.Fatalf("expected %v, got %v", testCase.expected, got)
			}
		})
	}
}
