package notification

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pinguinclient "github.com/tyemirov/pinguin/pkg/client"
	"github.com/tyemirov/pinguin/pkg/grpcapi"
	"github.com/tyemirov/tauth/internal/authkit"
)

const (
	emailVerificationSubject = "Verify your email"
	emailVerificationMessage = "Verify your email address with this link: %s\n\nThis link expires at %s."
	passwordResetSubject     = "Reset your password"
	passwordResetMessage     = "Reset your password with this link: %s\n\nThis link expires at %s."
	passwordLinkSubject      = "Confirm your email"
	passwordLinkMessage      = "Confirm this email address for your account with this link: %s\n\nThis link expires at %s."
)

type emailChallengeTemplate struct {
	subject string
	message string
}

var emailChallengeTemplates = map[authkit.EmailChallengeKind]emailChallengeTemplate{
	authkit.EmailChallengeKindVerification:  {subject: emailVerificationSubject, message: emailVerificationMessage},
	authkit.EmailChallengeKindPasswordReset: {subject: passwordResetSubject, message: passwordResetMessage},
	authkit.EmailChallengeKindPasswordLink:  {subject: passwordLinkSubject, message: passwordLinkMessage},
}

// PinguinTenantConfig configures one tenant connection to Pinguin.
type PinguinTenantConfig struct {
	TenantID                 string
	ServerAddress            string
	APIKey                   string
	ConnectionTimeoutSeconds int
	OperationTimeoutSeconds  int
}

type pinguinTenantClient struct {
	client           *pinguinclient.NotificationClient
	operationTimeout time.Duration
}

// PinguinEmailChallengeSender queues password-account email through Pinguin.
type PinguinEmailChallengeSender struct {
	clients map[string]pinguinTenantClient
}

// NewPinguinEmailChallengeSender creates a tenant-specific Pinguin sender.
func NewPinguinEmailChallengeSender(logger *slog.Logger, configs []PinguinTenantConfig) (*PinguinEmailChallengeSender, error) {
	if logger == nil {
		return nil, fmt.Errorf("notification.pinguin.logger_missing")
	}
	clients := make(map[string]pinguinTenantClient, len(configs))
	for _, config := range configs {
		tenantID := strings.TrimSpace(config.TenantID)
		if tenantID == "" {
			closePinguinClients(clients)
			return nil, fmt.Errorf("notification.pinguin.tenant_missing")
		}
		if _, exists := clients[tenantID]; exists {
			closePinguinClients(clients)
			return nil, fmt.Errorf("notification.pinguin.tenant_duplicate: %s", tenantID)
		}
		settings, settingsErr := pinguinclient.NewSettings(
			config.ServerAddress,
			config.APIKey,
			config.ConnectionTimeoutSeconds,
			config.OperationTimeoutSeconds,
		)
		if settingsErr != nil {
			closePinguinClients(clients)
			return nil, fmt.Errorf("notification.pinguin.settings tenant=%s: %w", tenantID, settingsErr)
		}
		client, clientErr := pinguinclient.NewNotificationClient(logger, settings)
		if clientErr != nil {
			closePinguinClients(clients)
			return nil, fmt.Errorf("notification.pinguin.client tenant=%s: %w", tenantID, clientErr)
		}
		clients[tenantID] = pinguinTenantClient{
			client:           client,
			operationTimeout: settings.OperationTimeout(),
		}
	}
	return &PinguinEmailChallengeSender{clients: clients}, nil
}

// SendEmailChallenge queues one password-account email notification.
func (sender *PinguinEmailChallengeSender) SendEmailChallenge(ctx context.Context, request authkit.EmailChallengeRequest) error {
	tenantClient, exists := sender.clients[request.TenantID]
	if !exists {
		return fmt.Errorf("notification.pinguin.tenant_not_configured: %s", request.TenantID)
	}
	template, exists := emailChallengeTemplates[request.Kind]
	if !exists {
		return fmt.Errorf("notification.pinguin.challenge_kind_invalid: %s", request.Kind)
	}
	requestContext, cancelRequest := context.WithTimeout(ctx, tenantClient.operationTimeout)
	defer cancelRequest()
	response, sendErr := tenantClient.client.SendNotification(requestContext, &grpcapi.NotificationRequest{
		NotificationType: grpcapi.NotificationType_EMAIL,
		Recipient:        request.Recipient,
		Subject:          template.subject,
		Message:          fmt.Sprintf(template.message, request.PublicURL, request.ExpiresAt.Format(time.RFC3339)),
	})
	if sendErr != nil {
		return fmt.Errorf("notification.pinguin.send tenant=%s: %w", request.TenantID, sendErr)
	}
	if response.Status != grpcapi.Status_QUEUED && response.Status != grpcapi.Status_SENT {
		return fmt.Errorf("notification.pinguin.status tenant=%s status=%s", request.TenantID, response.Status.String())
	}
	return nil
}

// Close releases all Pinguin connections.
func (sender *PinguinEmailChallengeSender) Close() error {
	return closePinguinClients(sender.clients)
}

func closePinguinClients(clients map[string]pinguinTenantClient) error {
	closeErrors := make([]error, 0, len(clients))
	for tenantID, tenantClient := range clients {
		if closeErr := tenantClient.client.Close(); closeErr != nil {
			closeErrors = append(closeErrors, fmt.Errorf("notification.pinguin.close tenant=%s: %w", tenantID, closeErr))
		}
	}
	return errors.Join(closeErrors...)
}
