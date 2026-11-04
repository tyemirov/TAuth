// Command retentionaudit reads private evidence for a bounded ownership handoff.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/tyemirov/tauth/internal/controlplane"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "retention.arguments_invalid")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, (64<<20)+1))
	if err != nil || len(payload) > 64<<20 {
		fmt.Fprintln(os.Stderr, "retention.request_invalid")
		os.Exit(2)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request controlplane.RetentionAuditRequest
	if err := decoder.Decode(&request); err != nil {
		fmt.Fprintln(os.Stderr, "retention.request_invalid")
		os.Exit(2)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fmt.Fprintln(os.Stderr, "retention.request_invalid")
		os.Exit(2)
	}
	result, err := controlplane.AuditRetention(ctx, request)
	if err != nil {
		// Errors contain fixed codes. Private provider values never enter logs.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "retention.output_failed")
		os.Exit(1)
	}
}
