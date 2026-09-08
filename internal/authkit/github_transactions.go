package authkit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

const (
	githubTransactionTTL      = 5 * time.Minute
	githubTransactionCapacity = 4096
	githubStoreErrorPrefix    = "github_login_store"
)

var (
	ErrGitHubStateInvalid = errors.New("invalid_state")
	ErrGitHubStoreFull    = errors.New("github_login_capacity")
)

type githubOperation string

const (
	githubSessionLogin      githubOperation = "session"
	githubAccountLink       githubOperation = "link"
	githubOAuthContinuation githubOperation = "oauth"
)

type githubTransaction struct {
	StateHash     string `gorm:"primaryKey"`
	BrowserHash   string
	TenantID      string
	ClientID      string
	RedirectURI   string
	Verifier      string
	CreatedAtUnix int64
	ExpiresAtUnix int64 `gorm:"index"`
	Operation     githubOperation
	AccountID     string
	OAuthRequest  string
	ReturnTo      string
	PopupOrigin   string
	Correlation   string
}

func (githubTransaction) TableName() string { return "github_login_transactions" }

// GitHubTransactionStore atomically consumes browser-bound login transactions.
type GitHubTransactionStore interface {
	create(context.Context, githubTransaction) error
	claim(context.Context, string, string, int64) (githubTransaction, error)
}

type memoryGitHubTransactions struct {
	mutex        sync.Mutex
	transactions map[string]githubTransaction
}

// NewMemoryGitHubTransactionStore constructs a bounded, five-minute transaction store.
func NewMemoryGitHubTransactionStore() GitHubTransactionStore {
	return &memoryGitHubTransactions{transactions: make(map[string]githubTransaction)}
}

func (store *memoryGitHubTransactions) create(ctx context.Context, transaction githubTransaction) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("github_login_store.create: %w", err)
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for key, pending := range store.transactions {
		if pending.ExpiresAtUnix <= transaction.CreatedAtUnix {
			delete(store.transactions, key)
		}
	}
	if len(store.transactions) >= githubTransactionCapacity {
		return ErrGitHubStoreFull
	}
	if _, exists := store.transactions[transaction.StateHash]; exists {
		return ErrGitHubStateInvalid
	}
	store.transactions[transaction.StateHash] = transaction
	return nil
}

func (store *memoryGitHubTransactions) claim(ctx context.Context, stateHash, browserHash string, now int64) (githubTransaction, error) {
	if err := ctx.Err(); err != nil {
		return githubTransaction{}, fmt.Errorf("github_login_store.claim: %w", err)
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	transaction, exists := store.transactions[stateHash]
	if !exists || transaction.BrowserHash != browserHash {
		return githubTransaction{}, ErrGitHubStateInvalid
	}
	delete(store.transactions, stateHash)
	if transaction.ExpiresAtUnix <= now {
		return githubTransaction{}, ErrGitHubStateInvalid
	}
	return transaction, nil
}

type databaseGitHubTransactions struct{ db *gorm.DB }

// NewDatabaseGitHubTransactionStore uses the configured SQLite or PostgreSQL database.
func NewDatabaseGitHubTransactionStore(ctx context.Context, databaseURL string) (GitHubTransactionStore, error) {
	database, _, err := openDatabase(ctx, databaseURL, githubStoreErrorPrefix, &githubTransaction{})
	if err != nil {
		return nil, err
	}
	return &databaseGitHubTransactions{db: database}, nil
}

func (store *databaseGitHubTransactions) create(ctx context.Context, transaction githubTransaction) error {
	if err := store.db.WithContext(ctx).Where("expires_at_unix <= ?", transaction.CreatedAtUnix).Delete(&githubTransaction{}).Error; err != nil {
		return fmt.Errorf("github_login_store.purge: %w", err)
	}
	if err := store.db.WithContext(ctx).Create(&transaction).Error; err != nil {
		return fmt.Errorf("github_login_store.create: %w", err)
	}
	return nil
}

func (store *databaseGitHubTransactions) claim(ctx context.Context, stateHash, browserHash string, now int64) (githubTransaction, error) {
	var transaction githubTransaction
	query := store.db.WithContext(ctx).Where("state_hash = ? AND browser_hash = ? AND expires_at_unix > ?", stateHash, browserHash, now)
	if err := query.Take(&transaction).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return githubTransaction{}, ErrGitHubStateInvalid
		}
		return githubTransaction{}, fmt.Errorf("github_login_store.read: %w", err)
	}
	result := store.db.WithContext(ctx).Where("state_hash = ? AND browser_hash = ? AND expires_at_unix > ?", stateHash, browserHash, now).Delete(&githubTransaction{})
	if result.Error != nil {
		return githubTransaction{}, fmt.Errorf("github_login_store.claim: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return githubTransaction{}, ErrGitHubStateInvalid
	}
	return transaction, nil
}
