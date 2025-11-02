package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

const refreshOpaqueByteLength = 32

func newRefreshTokenID(now time.Time) string {
	nowString := now.UTC().Format(time.RFC3339Nano)
	return base64.RawURLEncoding.EncodeToString([]byte(nowString))
}

func generateRefreshOpaque() (string, string, error) {
	randomBytes := make([]byte, refreshOpaqueByteLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("refresh_store.random: %w", err)
	}
	opaque := base64.RawURLEncoding.EncodeToString(randomBytes)
	return opaque, hashOpaque(opaque), nil
}

func hashOpaque(opaque string) string {
	sum := sha256.Sum256([]byte(opaque))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
