package notification

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tyemirov/pinguin/pkg/grpcapi"
	"github.com/tyemirov/tauth/internal/authkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type recordingNotificationService struct {
	grpcapi.UnimplementedNotificationServiceServer
	requests      chan *grpcapi.NotificationRequest
	authorization chan string
}

func (service *recordingNotificationService) SendNotification(ctx context.Context, request *grpcapi.NotificationRequest) (*grpcapi.NotificationResponse, error) {
	incomingMetadata, _ := metadata.FromIncomingContext(ctx)
	authorizationValues := incomingMetadata.Get("authorization")
	if len(authorizationValues) == 1 {
		service.authorization <- authorizationValues[0]
	}
	service.requests <- request
	return &grpcapi.NotificationResponse{
		NotificationId:   "notification-one",
		NotificationType: grpcapi.NotificationType_EMAIL,
		Status:           grpcapi.Status_QUEUED,
	}, nil
}

func TestPinguinSenderQueuesPasswordChallengeEmails(testingHandle *testing.T) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		testingHandle.Fatalf("listen for Pinguin test service: %v", listenErr)
	}
	grpcServer := grpc.NewServer()
	recordingService := &recordingNotificationService{
		requests:      make(chan *grpcapi.NotificationRequest, 3),
		authorization: make(chan string, 3),
	}
	grpcapi.RegisterNotificationServiceServer(grpcServer, recordingService)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	sender, senderErr := NewPinguinEmailChallengeSender(slog.Default(), []PinguinTenantConfig{{
		TenantID:                 "tenant-a",
		ServerAddress:            listener.Addr().String(),
		APIKey:                   "test-api-key",
		ConnectionTimeoutSeconds: 2,
		OperationTimeoutSeconds:  2,
	}})
	if senderErr != nil {
		testingHandle.Fatalf("create Pinguin sender: %v", senderErr)
	}
	defer sender.Close()

	testCases := []struct {
		name    string
		kind    authkit.EmailChallengeKind
		subject string
	}{
		{name: "email verification", kind: authkit.EmailChallengeKindVerification, subject: "Verify your email"},
		{name: "password reset", kind: authkit.EmailChallengeKindPasswordReset, subject: "Reset your password"},
		{name: "password link", kind: authkit.EmailChallengeKindPasswordLink, subject: "Confirm your email"},
	}
	for _, testCase := range testCases {
		testingHandle.Run(testCase.name, func(testingHandle *testing.T) {
			deliveryRequest := authkit.EmailChallengeRequest{
				Kind:      testCase.kind,
				TenantID:  "tenant-a",
				Recipient: "new@example.com",
				PublicURL: "https://ui.example.com/auth#secret-token",
				ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			}
			if deliveryErr := sender.SendEmailChallenge(context.Background(), deliveryRequest); deliveryErr != nil {
				testingHandle.Fatalf("queue challenge email: %v", deliveryErr)
			}

			select {
			case request := <-recordingService.requests:
				if request.NotificationType != grpcapi.NotificationType_EMAIL || request.Recipient != deliveryRequest.Recipient {
					testingHandle.Fatalf("unexpected Pinguin request: %#v", request)
				}
				if request.Subject != testCase.subject {
					testingHandle.Fatalf("unexpected challenge subject: %q", request.Subject)
				}
				if !strings.Contains(request.Message, deliveryRequest.PublicURL) {
					testingHandle.Fatalf("challenge message has no public URL: %q", request.Message)
				}
			case <-time.After(time.Second):
				testingHandle.Fatal("Pinguin did not receive a challenge request")
			}
		})
	}

	for range testCases {
		select {
		case authorization := <-recordingService.authorization:
			if authorization != "Bearer test-api-key" {
				testingHandle.Fatalf("unexpected Pinguin authorization: %q", authorization)
			}
		case <-time.After(time.Second):
			testingHandle.Fatal("Pinguin did not receive authorization metadata")
		}
	}
}
