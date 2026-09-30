package authkit

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrAuthenticationRateLimited means the request exceeded an authentication budget.
var ErrAuthenticationRateLimited = errors.New("auth.rate_limited")

const maximumAbuseBudgetRecords = 10000
const maximumResetChallenges = 10000

type requestSourceKey struct{}

func withRequestSource(ctx context.Context, request *http.Request) context.Context {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	return context.WithValue(ctx, requestSourceKey{}, host)
}

type abuseBudget struct {
	key   string
	limit int
}
type abuseBudgetRecord struct {
	Key         string `gorm:"primaryKey"`
	Attempts    int    `gorm:"not null"`
	ExpiresUnix int64  `gorm:"index;not null"`
}

func (abuseBudgetRecord) TableName() string { return "auth_abuse_budgets" }

type abuseBudgetLock struct {
	ID int `gorm:"primaryKey"`
}

func (abuseBudgetLock) TableName() string { return "auth_abuse_budget_lock" }

func authenticationBudgets(ctx context.Context, operation, tenantID, email string, accountLimit, sourceLimit int) []abuseBudget {
	source, _ := ctx.Value(requestSourceKey{}).(string)
	return []abuseBudget{
		{key: hashOpaque(operation + "\x00account\x00" + tenantID + "\x00" + email), limit: accountLimit},
		{key: hashOpaque(operation + "\x00source\x00" + source), limit: sourceLimit},
		{key: hashOpaque(operation + "\x00global"), limit: 1000},
	}
}

func (store *MemoryPasswordCredentialStore) reserveAuthenticationBudget(ctx context.Context, operation, tenantID, email string, accountLimit, sourceLimit int) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now().Unix()
	for key, record := range store.abuseBudgets {
		if record.ExpiresUnix <= now {
			delete(store.abuseBudgets, key)
		}
	}
	budgets := authenticationBudgets(ctx, operation, tenantID, email, accountLimit, sourceLimit)
	missing := 0
	for _, budget := range budgets {
		record, exists := store.abuseBudgets[budget.key]
		if exists && record.Attempts >= budget.limit {
			return ErrAuthenticationRateLimited
		}
		if !exists {
			missing++
		}
	}
	if len(store.abuseBudgets)+missing > maximumAbuseBudgetRecords {
		return ErrAuthenticationRateLimited
	}
	for _, budget := range budgets {
		record, exists := store.abuseBudgets[budget.key]
		if !exists {
			record = abuseBudgetRecord{Key: budget.key, ExpiresUnix: now + int64(time.Minute/time.Second)}
		}
		record.Attempts++
		store.abuseBudgets[budget.key] = record
	}
	return nil
}

func (store *DatabaseUserStore) reserveAuthenticationBudget(ctx context.Context, operation, tenantID, email string, accountLimit, sourceLimit int) error {
	var rejected bool
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// This first write serializes budget admission across processes on both supported databases.
		if err := tx.Model(&abuseBudgetLock{}).Where("id = ?", 1).Update("id", 1).Error; err != nil {
			return err
		}
		now := store.now().Unix()
		if err := tx.Where("expires_unix <= ?", now).Delete(&abuseBudgetRecord{}).Error; err != nil {
			return err
		}
		budgets := authenticationBudgets(ctx, operation, tenantID, email, accountLimit, sourceLimit)
		records := make([]abuseBudgetRecord, 0, len(budgets))
		missing := int64(0)
		for _, budget := range budgets {
			var record abuseBudgetRecord
			err := tx.Where("key = ?", budget.key).Take(&record).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				missing++
				record = abuseBudgetRecord{Key: budget.key, ExpiresUnix: now + int64(time.Minute/time.Second)}
			} else if err != nil {
				return err
			}
			if record.Attempts >= budget.limit {
				rejected = true
				return nil
			}
			record.Attempts++
			records = append(records, record)
		}
		var count int64
		if err := tx.Model(&abuseBudgetRecord{}).Count(&count).Error; err != nil {
			return err
		}
		if count+missing > maximumAbuseBudgetRecords {
			rejected = true
			return nil
		}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoUpdates: clause.AssignmentColumns([]string{"attempts", "expires_unix"})}).Create(&records).Error
	})
	if err != nil {
		return err
	}
	if rejected {
		return ErrAuthenticationRateLimited
	}
	return nil
}
