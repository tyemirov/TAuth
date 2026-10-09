package web_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/tyemirov/tauth/internal/web"
)

func TestInMemoryUsersOwnReturnedRoles(t *testing.T) {
	for _, operation := range []string{"upsert", "profile"} {
		t.Run(operation, func(t *testing.T) {
			store := web.NewInMemoryUsers()
			userID, roles, err := store.UpsertAccountUser(context.Background(), "tenant", "account", "user@example.com", "User", "avatar")
			if err != nil {
				t.Fatal(err)
			}
			if operation == "profile" {
				_, _, _, roles, err = store.GetUserProfile(context.Background(), "tenant", userID)
				if err != nil {
					t.Fatal(err)
				}
			}
			roles[0] = "admin"
			email, display, avatar, storedRoles, err := store.GetUserProfile(context.Background(), "tenant", userID)
			if err != nil || email != "user@example.com" || display != "User" || avatar != "avatar" || !slices.Equal(storedRoles, []string{"user"}) {
				t.Fatalf("mutating %s result changed stored profile: email=%q display=%q avatar=%q roles=%v err=%v", operation, email, display, avatar, storedRoles, err)
			}
		})
	}
}

func TestInMemoryUsersConcurrentProfilesAndReturnedRoles(t *testing.T) {
	store := web.NewInMemoryUsers()
	ctx := context.Background()
	if _, _, err := store.UpsertAccountUser(ctx, "tenant", "shared", "shared@example.com", "Shared", "avatar"); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	const iterations = 64
	ready := make(chan struct{})
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for worker := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-ready
			for iteration := range iterations {
				// All callers use one account so writes and reads share a map and profile.
				_, roles, err := store.UpsertAccountUser(ctx, "tenant", "shared", "shared@example.com", "Shared", "avatar")
				if err != nil {
					errors <- err
					return
				}
				roles[0] = fmt.Sprintf("caller-%d-%d", worker, iteration)
				email, display, avatar, profileRoles, err := store.GetUserProfile(ctx, "tenant", "shared")
				if err != nil || email != "shared@example.com" || display != "Shared" || avatar != "avatar" || !slices.Equal(profileRoles, []string{"user"}) {
					errors <- fmt.Errorf("concurrent profile: email=%q display=%q avatar=%q roles=%v err=%v", email, display, avatar, profileRoles, err)
					return
				}
				profileRoles[0] = "caller-owned"
			}
		}()
	}
	close(ready)
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	_, _, _, roles, err := store.GetUserProfile(ctx, "tenant", "shared")
	if err != nil || !slices.Equal(roles, []string{"user"}) {
		t.Fatalf("final stored roles=%v err=%v", roles, err)
	}
}
