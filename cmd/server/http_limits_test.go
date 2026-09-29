package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/testconfig"
)

func TestSecurityServerReadDeadline(t *testing.T) {
	restore := withServeHTTPStub(func(server *http.Server) error {
		if server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
			t.Fatal("server requires finite read, write, and idle timeouts")
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		defer func() { server.Close(); <-done }()
		connection, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(server.ReadTimeout + 2*time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(connection, "POST /auth/google HTTP/1.1\r\nHost: localhost\r\nOrigin: https://alpha.localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), nil)
		if err != nil {
			t.Fatalf("slow body should receive a bounded rejection: %v", err)
		}
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatalf("slow request accepted: %d", response.StatusCode)
		}
		return http.ErrServerClosed
	})
	defer restore()
	restoreValidator := withGoogleValidatorBuilderStub(func(context.Context) (authkit.GoogleTokenValidator, error) { return noopGoogleValidator{}, nil })
	defer restoreValidator()
	cfg := sampleApplicationConfig()
	cfg.Server.DatabaseURL = "sqlite://" + filepath.Join(t.TempDir(), "service.db")
	command := &cobra.Command{}
	command.SetContext(context.WithValue(context.Background(), appConfigContextKey, testconfig.Prepare(t, cfg)))
	if err := runServer(command, nil); err != nil {
		t.Fatal(err)
	}
}
