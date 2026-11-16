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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

// The service name is literal: deriving both ends from the same generated SDK
// would let an obsolete client and fixture agree on the wrong wire contract.
func TestPinguinSenderCanonicalWireContract(t *testing.T) {
	for _, scenario := range []struct {
		name           string
		responseStatus grpcapi.Status
		failure        codes.Code
		deadline       bool
		wantError      string
	}{
		{name: "queued", responseStatus: grpcapi.Status_QUEUED},
		{name: "sent", responseStatus: grpcapi.Status_SENT},
		{name: "errored", responseStatus: grpcapi.Status_ERRORED, wantError: "ERRORED"},
		{name: "unknown", responseStatus: grpcapi.Status_UNKNOWN, wantError: "UNKNOWN"},
		{name: "rejected_key", failure: codes.Unauthenticated, wantError: "Unauthenticated"},
		{name: "unavailable", failure: codes.Unavailable, wantError: "Unavailable"},
		{name: "deadline", deadline: true, wantError: "DeadlineExceeded"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			type observation struct {
				method          string
				request         *grpcapi.NotificationRequest
				authorization   []string
				tenantSelectors []string
				remaining       time.Duration
			}
			observed := make(chan observation, 1)
			server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
				method, _ := grpc.MethodFromServerStream(stream)
				if method != "/pingwin.NotificationService/SendNotification" {
					return status.Error(codes.Unimplemented, "noncanonical notification service")
				}
				request := new(grpcapi.NotificationRequest)
				if err := stream.RecvMsg(request); err != nil {
					return err
				}
				incoming, _ := metadata.FromIncomingContext(stream.Context())
				deadline, ok := stream.Context().Deadline()
				remaining := time.Duration(0)
				if ok {
					remaining = time.Until(deadline)
				}
				observed <- observation{method: method, request: request, authorization: incoming.Get("authorization"), tenantSelectors: incoming.Get("x-tenant-id"), remaining: remaining}
				if scenario.deadline {
					<-stream.Context().Done()
					return status.FromContextError(stream.Context().Err()).Err()
				}
				if scenario.failure != codes.OK {
					return status.Error(scenario.failure, "injected notification rejection")
				}
				return stream.SendMsg(&grpcapi.NotificationResponse{NotificationId: "wire-notification", NotificationType: grpcapi.NotificationType_EMAIL, Status: scenario.responseStatus})
			}))
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()
			sender, err := NewPinguinEmailChallengeSender(slog.Default(), []PinguinTenantConfig{{TenantID: "wire-tenant", ServerAddress: listener.Addr().String(), APIKey: "wire-api-key", ConnectionTimeoutSeconds: 1, OperationTimeoutSeconds: 1}})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			ctx := context.Background()
			request := authkit.EmailChallengeRequest{Kind: authkit.EmailChallengeKindVerification, TenantID: "wire-tenant", Recipient: "wire@example.com", PublicURL: "https://app.example.com/verify#one-use-challenge", ExpiresAt: time.Now().UTC().Add(time.Hour)}
			err = sender.SendEmailChallenge(ctx, request)
			if scenario.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), scenario.wantError) {
				t.Fatalf("expected %s, got %v", scenario.wantError, err)
			}
			select {
			case wire := <-observed:
				if wire.method != "/pingwin.NotificationService/SendNotification" || wire.request.NotificationType != grpcapi.NotificationType_EMAIL || wire.request.Recipient != request.Recipient || !strings.Contains(wire.request.Message, request.PublicURL) {
					t.Fatal("wire method or challenge intent changed")
				}
				if len(wire.authorization) != 1 || wire.authorization[0] != "Bearer wire-api-key" || len(wire.tenantSelectors) != 0 {
					t.Fatal("notification authentication boundary changed")
				}
				if wire.remaining <= 0 || wire.remaining > time.Second+100*time.Millisecond {
					t.Fatalf("missing operation deadline: %s", wire.remaining)
				}
			case <-time.After(time.Second):
				t.Fatal("canonical notification RPC was not observed")
			}
		})
	}
}
