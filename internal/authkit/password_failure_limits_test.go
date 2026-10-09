package authkit

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordProgressiveScheduleAndExistingHash(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			var store PasswordCredentialStore
			var compares atomic.Int32
			comparer := func(hash, password []byte) error {
				compares.Add(1)
				return bcrypt.CompareHashAndPassword(hash, password)
			}
			now := time.Unix(1800000000, 900000000)
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.now = func() time.Time { return now }
				memory.passwordHashComparer = comparer
				store = memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				database.passwordHashComparer = comparer
				store = database
			}
			hash, err := bcrypt.GenerateFromPassword([]byte("short"), bcrypt.DefaultCost)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertPasswordCredential(context.Background(), "tenant", PasswordCredentialSeed{UserEmail: "known@example.com", PasswordHash: string(hash)}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.AuthenticatePassword(context.Background(), "tenant", "known@example.com", "short"); err != nil {
				t.Fatal(err)
			}
			for index, seconds := range []int{1, 2, 4, 8, 16, 32, 60, 60} {
				if index == 4 {
					now = now.Add(time.Minute)
				} // Fixed request windows remain independently enforced.
				if _, err := store.AuthenticatePassword(context.Background(), "tenant", "known@example.com", "wrong"); !errors.Is(err, ErrPasswordCredentialInvalid) {
					t.Fatalf("failure %d: %v", index, err)
				}
				before := compares.Load()
				_, err := store.AuthenticatePassword(context.Background(), "tenant", "known@example.com", "short")
				if !errors.Is(err, ErrAuthenticationRateLimited) || AuthenticationRetryAfter(err) != seconds || compares.Load() != before {
					t.Fatalf("delay %d: err=%v retry=%d bcrypt=%d", index, err, AuthenticationRetryAfter(err), compares.Load()-before)
				}
				now = now.Add(time.Duration(seconds) * time.Second)
				// Denied requests consume fixed budgets; advance to a new window after each two admissions.
				if index == 1 || index == 3 || index == 5 {
					now = now.Add(time.Minute)
				}
			}
			now = now.Add(passwordFailureExpiry)
			if _, err := store.AuthenticatePassword(context.Background(), "tenant", "known@example.com", "short"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.AuthenticatePassword(context.Background(), "tenant", "known@example.com", "short"); err != nil {
				t.Fatalf("success failed to clear delay: %v", err)
			}
		})
	}
}

func TestPasswordStrengthUnicode(t *testing.T) {
	for _, password := range []string{"x", strings.Repeat("界", 14), string([]byte{0xff}) + strings.Repeat("a", 15), strings.Repeat("a", 73)} {
		if _, err := HashPassword(password); err == nil {
			t.Fatal("invalid new password accepted")
		}
	}
	for _, password := range []string{strings.Repeat("界", 15), strings.Repeat("a", 72)} {
		if _, err := HashPassword(password); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPasswordConcurrentReservationTickets(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		for _, recreation := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recreation=%v", backend, recreation), func(t *testing.T) {
				var clock atomic.Int64
				clock.Store(time.Now().UnixNano())
				now := func() time.Time { return time.Unix(0, clock.Load()) }
				var primary, secondary PasswordCredentialStore
				entered, release := make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				comparer := func(_ []byte, password []byte) error {
					if calls.Add(1) == 1 {
						close(entered)
						<-release
					}
					if string(password) == "correct horse battery staple" {
						return nil
					}
					return errors.New("mismatch")
				}
				if backend == "memory" {
					store := NewMemoryPasswordCredentialStore()
					store.now = now
					store.passwordHashComparer = comparer
					primary, secondary = store, store
				} else {
					databaseURL := sqliteDatabaseURL(t)
					store, err := NewDatabaseUserStore(context.Background(), databaseURL)
					if err != nil {
						t.Fatal(err)
					}
					other, err := NewDatabaseUserStore(context.Background(), databaseURL)
					if err != nil {
						t.Fatal(err)
					}
					store.now, other.now = now, now
					store.passwordHashComparer, other.passwordHashComparer = comparer, comparer
					primary, secondary = store, other
				}
				hash, err := HashPassword("correct horse battery staple")
				if err != nil {
					t.Fatal(err)
				}
				if err := primary.UpsertPasswordCredential(context.Background(), "tenant", PasswordCredentialSeed{UserEmail: "user@example.com", PasswordHash: hash}); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					_, err := primary.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "correct horse battery staple")
					result <- err
				}()
				<-entered
				if _, err := secondary.AuthenticatePassword(context.Background(), "tenant", "USER@example.com", "correct horse battery staple"); !errors.Is(err, ErrAuthenticationRateLimited) {
					t.Fatalf("concurrent bypass: %v", err)
				}
				if calls.Load() != 1 {
					t.Fatal("rejected concurrent attempt ran bcrypt")
				}
				if recreation {
					clock.Add(int64(passwordFailureExpiry))
				} else {
					clock.Add(int64(time.Second))
					if _, err := secondary.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "correct horse battery staple"); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := secondary.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "wrong"); !errors.Is(err, ErrPasswordCredentialInvalid) {
					t.Fatal(err)
				}
				close(release)
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				before := calls.Load()
				if _, err := secondary.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "correct horse battery staple"); !errors.Is(err, ErrAuthenticationRateLimited) || AuthenticationRetryAfter(err) != 1 {
					t.Fatalf("old success erased new failure: %v", err)
				}
				if calls.Load() != before {
					t.Fatal("delay rejection ran bcrypt")
				}
			})
		}
	}
}

func TestPasswordCanceledAttemptRemainsCharged(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			var store PasswordCredentialStore
			ctx, cancel := context.WithCancel(context.Background())
			comparer := func(_ []byte, _ []byte) error { cancel(); return nil }
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.passwordHashComparer = comparer
				store = memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.passwordHashComparer = comparer
				store = database
			}
			hash, err := HashPassword("correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertPasswordCredential(context.Background(), "tenant", PasswordCredentialSeed{UserEmail: "user@example.com", PasswordHash: hash}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.AuthenticatePassword(ctx, "tenant", "user@example.com", "correct horse battery staple"); err == nil {
				t.Fatal("canceled login succeeded")
			}
			if _, err := store.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "correct horse battery staple"); !errors.Is(err, ErrAuthenticationRateLimited) {
				t.Fatalf("canceled reservation lost: %v", err)
			}
		})
	}
}

func TestPasswordFailureCapacityAndPersistenceError(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			var store PasswordCredentialStore
			now := time.Now()
			records := make([]passwordFailureRecord, maximumPasswordFailureRecords)
			for index := range records {
				records[index] = passwordFailureRecord{Key: fmt.Sprintf("capacity-%d", index), Ticket: "ticket", Failures: 1, NextAllowedUnixNano: now.Add(time.Second).UnixNano(), ExpiresUnixNano: now.Add(passwordFailureExpiry).UnixNano()}
			}
			var compares atomic.Int32
			comparer := func(_ []byte, _ []byte) error { compares.Add(1); return errors.New("mismatch") }
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.now = func() time.Time { return now }
				memory.passwordHashComparer = comparer
				for _, record := range records {
					memory.passwordFailures[record.Key] = record
				}
				store = memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				database.passwordHashComparer = comparer
				if err := database.db.CreateInBatches(records, 100).Error; err != nil {
					t.Fatal(err)
				}
				store = database
			}
			if _, err := store.AuthenticatePassword(context.Background(), "tenant", "missing@example.com", "wrong"); !errors.Is(err, ErrAuthenticationRateLimited) {
				t.Fatalf("capacity bypass: %v", err)
			}
			if compares.Load() != 0 {
				t.Fatal("capacity rejection ran bcrypt")
			}
			if database, ok := store.(*DatabaseUserStore); ok {
				if err := database.db.Migrator().DropTable(&passwordFailureRecord{}); err != nil {
					t.Fatal(err)
				}
				_, err := store.AuthenticatePassword(context.Background(), "tenant", "other@example.com", "wrong")
				if err == nil || errors.Is(err, ErrAuthenticationRateLimited) || errors.Is(err, ErrPasswordCredentialInvalid) {
					t.Fatalf("persistence error hidden: %v", err)
				}
			}
		})
	}
}

func TestPasswordDelayRoundingAndTenantScope(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			var store PasswordCredentialStore
			now := time.Unix(1800000000, 900000000)
			comparer := func(_ []byte, _ []byte) error { return errors.New("mismatch") }
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.now = func() time.Time { return now }
				memory.passwordHashComparer = comparer
				store = memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				database.passwordHashComparer = comparer
				store = database
			}
			_, err := store.AuthenticatePassword(context.Background(), "tenant-a", "missing@example.com", "wrong")
			if !errors.Is(err, ErrPasswordCredentialInvalid) {
				t.Fatal(err)
			}
			now = now.Add(500 * time.Millisecond)
			_, err = store.AuthenticatePassword(context.Background(), "tenant-a", "missing@example.com", "wrong")
			if !errors.Is(err, ErrAuthenticationRateLimited) || AuthenticationRetryAfter(err) != 1 {
				t.Fatalf("fractional retry: %v", err)
			}
			_, err = store.AuthenticatePassword(context.Background(), "tenant-b", "missing@example.com", "wrong")
			if !errors.Is(err, ErrPasswordCredentialInvalid) {
				t.Fatalf("tenant state leaked: %v", err)
			}
			now = now.Add(500 * time.Millisecond)
			_, err = store.AuthenticatePassword(context.Background(), "tenant-a", "missing@example.com", "wrong")
			if !errors.Is(err, ErrPasswordCredentialInvalid) {
				t.Fatalf("full second failed: %v", err)
			}
		})
	}
}

func TestPasswordSuccessKeepsRequestBudget(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			var store PasswordCredentialStore
			var compares atomic.Int32
			comparer := func(_ []byte, _ []byte) error { compares.Add(1); return nil }
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.passwordHashComparer = comparer
				store = memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.passwordHashComparer = comparer
				store = database
			}
			hash, err := HashPassword("correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertPasswordCredential(context.Background(), "tenant", PasswordCredentialSeed{UserEmail: "user@example.com", PasswordHash: hash}); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 5; attempt++ {
				if _, err := store.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "correct horse battery staple"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.AuthenticatePassword(context.Background(), "tenant", "user@example.com", "correct horse battery staple"); !errors.Is(err, ErrAuthenticationRateLimited) || AuthenticationRetryAfter(err) != 60 {
				t.Fatalf("success erased fixed budget: %v", err)
			}
			if compares.Load() != 5 {
				t.Fatal("fixed budget rejection ran bcrypt")
			}
		})
	}
}
