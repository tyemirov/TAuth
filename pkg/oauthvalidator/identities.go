package oauthvalidator

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// ProviderIdentity is one verified immutable identity disclosed by the issuer.
type ProviderIdentity struct {
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
}

// NewProviderIdentity validates the canonical GitHub identity record.
func NewProviderIdentity(provider, providerID string) (ProviderIdentity, error) {
	identifier, err := strconv.ParseUint(providerID, 10, 64)
	if provider != "github" || err != nil || identifier == 0 || strconv.FormatUint(identifier, 10) != providerID {
		return ProviderIdentity{}, ErrInvalidToken
	}
	return ProviderIdentity{Provider: provider, ProviderID: providerID}, nil
}

// ProviderIdentities is the canonical nonempty identity claim when disclosure is granted.
type ProviderIdentities []ProviderIdentity

// UnmarshalJSON rejects unknown fields, duplicate fields, and noncanonical identities.
func (identities *ProviderIdentities) UnmarshalJSON(data []byte) error {
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil || len(records) == 0 {
		return ErrInvalidToken
	}
	result := make(ProviderIdentities, 0, len(records))
	seen := make(map[ProviderIdentity]struct{}, len(records))
	for _, record := range records {
		decoder := json.NewDecoder(bytes.NewReader(record))
		start, err := decoder.Token()
		if err != nil || start != json.Delim('{') {
			return ErrInvalidToken
		}
		fields := make(map[string]string, 2)
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil || (name != "provider" && name != "provider_id") {
				return ErrInvalidToken
			}
			key := name.(string)
			if _, exists := fields[key]; exists {
				return ErrInvalidToken
			}
			var value string
			if err := decoder.Decode(&value); err != nil {
				return ErrInvalidToken
			}
			fields[key] = value
		}
		if len(fields) != 2 {
			return ErrInvalidToken
		}
		identity, err := NewProviderIdentity(fields["provider"], fields["provider_id"])
		if err != nil {
			return err
		}
		if _, exists := seen[identity]; exists {
			return ErrInvalidToken
		}
		seen[identity] = struct{}{}
		result = append(result, identity)
	}
	*identities = result
	return nil
}
