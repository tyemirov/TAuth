package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

const refreshOpaqueByteLength = 32

var refreshTokenRandomSource io.Reader = rand.Reader

func newRefreshTokenID(now time.Time) string {
	nowString := now.UTC().Format(time.RFC3339Nano)
	return base64.RawURLEncoding.EncodeToString([]byte(nowString))
}

func generateRefreshOpaque() (string, string, error) {
	return generateOpaqueToken(refreshTokenRandomSource, refreshOpaqueByteLength, refreshStoreErrorPrefix)
}

func hashOpaque(opaque string) string {
	sum := sha256.Sum256([]byte(opaque))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func generateOpaqueToken(randomSource io.Reader, tokenSize int, errorPrefix string) (string, string, error) {
	randomBytes := make([]byte, tokenSize)
	if _, err := io.ReadFull(randomSource, randomBytes); err != nil {
		return "", "", fmt.Errorf("%s.random: %w", errorPrefix, err)
	}
	opaque := base64.RawURLEncoding.EncodeToString(randomBytes)
	return opaque, hashOpaque(opaque), nil
}
