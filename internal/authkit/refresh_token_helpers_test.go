package authkit

import (
	"bytes"
	"errors"
	"testing"
)

type failingRandomSource struct{}

func (f failingRandomSource) Read(p []byte) (int, error) {
	return 0, errors.New("forced failure")
}

func TestGenerateRefreshOpaqueError(t *testing.T) {
	original := refreshTokenRandomSource
	refreshTokenRandomSource = failingRandomSource{}
	defer func() { refreshTokenRandomSource = original }()

	_, _, err := generateRefreshOpaque()
	if err == nil {
		t.Fatalf("expected error when random source fails")
	}
}

func TestGenerateRefreshOpaqueDeterministicSource(t *testing.T) {
	original := refreshTokenRandomSource
	refreshTokenRandomSource = bytes.NewReader(bytes.Repeat([]byte{1}, refreshOpaqueByteLength))
	defer func() { refreshTokenRandomSource = original }()

	opaque, hashValue, err := generateRefreshOpaque()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opaque == "" || hashValue == "" {
		t.Fatalf("expected non-empty opaque and hash")
	}
}
