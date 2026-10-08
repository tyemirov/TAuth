package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeCleanupHTTPDoesNotBlockPublishedSnapshot(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	old := &runtimeSnapshot{handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), done: make(chan struct{}), cleanup: func() { calls.Add(1); close(entered); <-release }}
	publisher := &runtimePublisher{current: old}
	next := &runtimeSnapshot{handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), done: make(chan struct{}), cleanup: func() {}}
	prepared := &preparedSnapshot{publisher: publisher, snapshot: next}
	published := make(chan struct{})
	go func() { prepared.Publish(); close(published) }()
	<-entered
	server := httptest.NewServer(publisher)
	defer server.Close()
	responseReady := make(chan int, 1)
	go func() {
		response, err := server.Client().Get(server.URL + "/current")
		if err != nil {
			responseReady <- 0
			return
		}
		response.Body.Close()
		responseReady <- response.StatusCode
	}()
	select {
	case status := <-responseReady:
		if status != http.StatusOK {
			t.Errorf("published response=%d", status)
		}
	case <-time.After(time.Second):
		t.Error("retired cleanup blocked published HTTP traffic")
	}
	drained := make(chan error, 1)
	go func() { drained <- prepared.Drain(context.Background()) }()
	select {
	case err := <-drained:
		t.Errorf("drain finished before cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-published
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain did not join cleanup")
	}
	publisher.Close()
	publisher.Close()
	if calls.Load() != 1 {
		t.Fatalf("retired cleanup calls=%d", calls.Load())
	}
}
