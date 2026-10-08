package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const transientCleanupInterval = 30 * time.Second

type transientCleaner interface {
	CleanupExpired(context.Context, int64) error
}

type namedTransientStore struct {
	name  string
	store transientCleaner
}

func sweepTransientStores(ctx context.Context, stores []namedTransientStore, nowUnix int64) error {
	var failures []error
	for _, store := range stores {
		if err := store.store.CleanupExpired(ctx, nowUnix); err != nil {
			failures = append(failures, fmt.Errorf("transient_cleanup.%s: %w", store.name, err))
		}
	}
	return errors.Join(failures...)
}

// startTransientCleanup completes the startup sweep before it starts periodic work.
// Its stop function cancels and joins work before stores can be closed.
func startTransientCleanup(ctx context.Context, stores []namedTransientStore, now func() time.Time, ticks <-chan time.Time, reportError func(error)) (func(), error) {
	if err := sweepTransientStores(ctx, stores, now().UTC().Unix()); err != nil {
		return nil, err
	}
	workerContext, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-workerContext.Done():
				return
			case tick, open := <-ticks:
				if !open {
					return
				}
				if err := sweepTransientStores(workerContext, stores, tick.UTC().Unix()); err != nil && workerContext.Err() == nil {
					reportError(err)
				}
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}
