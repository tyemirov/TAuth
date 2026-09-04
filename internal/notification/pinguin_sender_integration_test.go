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

func TestPinguinSenderQueuesEmailVerification(testingHandle *testing.T) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		testingHandle.Fatalf("listen for Pinguin test service: %v", listenErr)
	}
	grpcServer := grpc.NewServer()
	recordingService := &recordingNotificationService{
		requests:      make(chan *grpcapi.NotificationRequest, 1),
		authorization: make(chan string, 1),
	}
	grpcapi.RegisterNotificationServiceServer(grpcServer, recordingService)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	sender, senderErr := NewPinguinEmailVerificationSender(slog.Default(), []PinguinTenantConfig{{
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

	verificationRequest := authkit.EmailVerificationRequest{
		TenantID:        "tenant-a",
		Recipient:       "new@example.com",
		VerificationURL: "https://ui.example.com/verify-email?token=secret-token",
		ExpiresAt:       time.Now().UTC().Add(30 * time.Minute),
	}
	if deliveryErr := sender.SendEmailVerification(context.Background(), verificationRequest); deliveryErr != nil {
		testingHandle.Fatalf("queue verification email: %v", deliveryErr)
	}

	select {
	case request := <-recordingService.requests:
		if request.NotificationType != grpcapi.NotificationType_EMAIL || request.Recipient != verificationRequest.Recipient {
			testingHandle.Fatalf("unexpected Pinguin request: %#v", request)
		}
		if request.Subject != "Verify your email" {
			testingHandle.Fatalf("unexpected verification subject: %q", request.Subject)
		}
		if !strings.Contains(request.Message, verificationRequest.VerificationURL) {
			testingHandle.Fatalf("verification message has no public URL: %q", request.Message)
		}
	case <-time.After(time.Second):
		testingHandle.Fatal("Pinguin did not receive a verification request")
	}

	select {
	case authorization := <-recordingService.authorization:
		if authorization != "Bearer test-api-key" {
			testingHandle.Fatalf("unexpected Pinguin authorization: %q", authorization)
		}
	case <-time.After(time.Second):
		testingHandle.Fatal("Pinguin did not receive authorization metadata")
	}
}
