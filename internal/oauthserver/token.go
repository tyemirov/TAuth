package oauthserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const opaqueTokenBytes = 32

func newOpaqueToken(subject string) (string, string, error) {
	raw := make([]byte, opaqueTokenBytes)
	if _, readErr := rand.Read(raw); readErr != nil {
		return "", "", fmt.Errorf("oauth.%s.random: %w", subject, readErr)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	return value, digestToken(value), nil
}

func digestToken(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
