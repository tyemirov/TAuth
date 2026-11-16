package tenants

// NativeGoogleAcquisitionFlow selects the native Google credential acquisition protocol.
type NativeGoogleAcquisitionFlow string

const (
	// NativeGoogleAuthorizationCode uses authorization code exchange with PKCE.
	NativeGoogleAuthorizationCode NativeGoogleAcquisitionFlow = "authorization_code"
	// NativeGoogleCredentialManager uses Android Credential Manager ID tokens.
	NativeGoogleCredentialManager NativeGoogleAcquisitionFlow = "google_credential_manager"
)

// Effective applies the canonical default for an omitted acquisition_flow.
func (flow NativeGoogleAcquisitionFlow) Effective() NativeGoogleAcquisitionFlow {
	if flow == "" {
		return NativeGoogleAuthorizationCode
	}
	return flow
}
