package authkit

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransientNonceCapacityHTTP(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			now := time.Now().UTC().Truncate(time.Second)
			var nonces NonceStore
			if backend == "memory" {
				store := NewMemoryNonceStore(time.Minute).(*memoryNonceStore)
				store.now = func() time.Time { return now }
				store.entries[config.TenantID] = map[string]time.Time{}
				for index := 0; index < 999; index++ {
					store.entries[config.TenantID][fmt.Sprint(index)] = now.Add(time.Minute)
				}
				nonces = store
			} else {
				store, err := NewDatabaseNonceStore(context.Background(), sqliteDatabaseURL(t), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				store.now = func() time.Time { return now }
				records := make([]nonceRecord, 999)
				for index := range records {
					records[index] = nonceRecord{TenantID: config.TenantID, TokenHash: fmt.Sprint(index), ExpiresUnix: now.Add(time.Minute).Unix()}
				}
				if err := store.db.Create(&records).Error; err != nil {
					t.Fatal(err)
				}
				nonces = store
			}
			router := gin.New()
			MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nonces, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
			server := httptest.NewServer(router)
			defer server.Close()
			for index, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
				response, err := server.Client().Post(server.URL+"/auth/nonce", "application/json", nil)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != want {
					t.Fatalf("request %d status=%d want=%d", index, response.StatusCode, want)
				}
			}
		})
	}
}

func TestTransientSignupCapacityHTTP(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			config := newTestServerConfig()
			config.PasswordAuthEnabled, config.AccountManagementEnabled, config.PasswordSignupEnabled = true, true, true
			sender := enableTestChallengeDelivery(&config)
			now := time.Now().UTC().Truncate(time.Second)
			var credentials PasswordCredentialStore
			if backend == "memory" {
				store := NewMemoryPasswordCredentialStore()
				store.now = func() time.Time { return now }
				store.ensureAccountMaps(config.TenantID)
				for index := 0; index < 999; index++ {
					id := fmt.Sprint(index)
					store.accounts[config.TenantID][id] = &accountRecord{accountID: id, state: accountStatePendingVerification}
					store.challenges[config.TenantID][id] = &accountChallengeRecord{accountID: id, kind: accountChallengeEmailVerification, expiresUnix: now.Add(time.Hour).Unix()}
				}
				credentials = store
			} else {
				store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				store.now = func() time.Time { return now }
				accounts := make([]databaseAccountRecord, 999)
				challenges := make([]databaseAccountChallengeRecord, 999)
				for index := range accounts {
					id := fmt.Sprint(index)
					accounts[index] = databaseAccountRecord{TenantID: config.TenantID, AccountID: id, UserID: id, AccountState: accountStatePendingVerification}
					challenges[index] = databaseAccountChallengeRecord{TenantID: config.TenantID, TokenHash: id, AccountID: id, ChallengeKind: accountChallengeEmailVerification, ExpiresUnix: now.Add(time.Hour).Unix()}
				}
				if err := store.db.CreateInBatches(&accounts, 100).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.db.CreateInBatches(&challenges, 100).Error; err != nil {
					t.Fatal(err)
				}
				credentials = store
			}
			router := gin.New()
			MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, credentials, newTestPasswordResetDispatcher(t), sender, nil)
			server := httptest.NewTLSServer(router)
			defer server.Close()
			for index, want := range []int{http.StatusAccepted, http.StatusTooManyRequests} {
				response := oneTimePost(t, server, "/auth/password/signup", fmt.Sprintf(`{"email":"new%d@example.com","password":"correct horse battery staple"}`, index))
				if response.StatusCode != want {
					t.Fatalf("signup%d status=%d want%d", index, response.StatusCode, want)
				}
				if len(response.Cookies()) != 0 {
					t.Fatal("signup returned credentials")
				}
			}
		})
	}
}

func TestTransientCleanupAccountEvidence(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			var store AccountManagementStore
			var cleanup interface {
				CleanupExpired(context.Context, int64) error
			}
			if backend == "memory" {
				memory := NewMemoryPasswordCredentialStore()
				memory.now = func() time.Time { return now }
				store, cleanup = memory, memory
			} else {
				database, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				store, cleanup = database, database
			}
			abandoned, err := store.CreatePasswordSignup(context.Background(), "tenant", AccountPasswordRequest{UserEmail: "abandoned@example.com", Password: "correct horse battery staple"}, now.Add(time.Minute).Unix())
			if err != nil {
				t.Fatal(err)
			}
			active, err := store.CreatePasswordSignup(context.Background(), "tenant", AccountPasswordRequest{UserEmail: "active@example.com", Password: "correct horse battery staple"}, now.Add(time.Minute).Unix())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.VerifyEmailChallenge(context.Background(), "tenant", active.Token); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			if err := cleanup.CleanupExpired(context.Background(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ResolveAccountProfile(context.Background(), "tenant", abandoned.AccountID); !errors.Is(err, ErrAccountNotFound) {
				t.Fatalf("abandoned account remains: %v", err)
			}
			if _, err := store.ResolveAccountProfile(context.Background(), "tenant", active.AccountID); err != nil {
				t.Fatalf("active account removed: %v", err)
			}
			switch concrete := store.(type) {
			case *MemoryPasswordCredentialStore:
				if len(concrete.challenges["tenant"]) != 0 || len(concrete.tenants["tenant"]) != 1 {
					t.Fatal("expired evidence or abandoned credential remains")
				}
			case *DatabaseUserStore:
				var count int64
				if err := concrete.db.Model(&databaseAccountChallengeRecord{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("challenge count%d error%v", count, err)
				}
				if err := concrete.db.Model(&passwordCredentialRecord{}).Count(&count).Error; err != nil || count != 1 {
					t.Fatalf("credential count%d error%v", count, err)
				}
			}
		})
	}
}

func TestTransientRefreshFamilyRetention(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			var store RefreshTokenStore
			var cleanup interface {
				CleanupExpired(context.Context, int64) error
			}
			var rows func() int
			if backend == "memory" {
				memory := NewMemoryRefreshTokenStore()
				memory.now = func() time.Time { return now }
				store, cleanup = memory, memory
				rows = func() int { return len(memory.byID) }
			} else {
				database, err := NewDatabaseRefreshTokenStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				seedApplicationSubject(t, database.db, "tenant", "user")
				store, cleanup = database, database
				rows = func() int {
					var count int64
					if err := database.db.Model(&refreshTokenRecord{}).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					return int(count)
				}
			}
			root, opaque, err := store.Issue(context.Background(), "tenant", "user", now.Add(time.Minute).Unix(), "")
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Nanosecond)
			_, child, err := store.Issue(context.Background(), "tenant", "user", now.Add(time.Hour).Unix(), root)
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			if err := cleanup.CleanupExpired(context.Background(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if rows() != 2 {
				t.Fatalf("expired ancestor removed, rows%d", rows())
			}
			if _, _, _, err := store.Validate(context.Background(), "tenant", opaque); !errors.Is(err, ErrRefreshTokenRevoked) {
				t.Fatalf("replay error%v", err)
			}
			if _, _, _, err := store.Validate(context.Background(), "tenant", child); !errors.Is(err, ErrRefreshTokenRevoked) {
				t.Fatalf("child survives replay%v", err)
			}
			now = now.Add(time.Hour)
			if err := cleanup.CleanupExpired(context.Background(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if rows() != 0 {
				t.Fatalf("expired family remains%d", rows())
			}
		})
	}
}

func TestTransientNonceCapacityMultipleDatabasesHTTP(t *testing.T) {
	config := newTestServerConfig()
	url := sqliteDatabaseURL(t)
	first, err := NewDatabaseNonceStore(context.Background(), url, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDatabaseNonceStore(context.Background(), url, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	records := make([]nonceRecord, 999)
	for index := range records {
		records[index] = nonceRecord{TenantID: config.TenantID, TokenHash: fmt.Sprint(index), ExpiresUnix: now + 3600}
	}
	if err := first.db.CreateInBatches(&records, 100).Error; err != nil {
		t.Fatal(err)
	}
	servers := make([]*httptest.Server, 2)
	for index, store := range []*DatabaseNonceStore{first, second} {
		router := gin.New()
		MountAuthRoutes(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), store, NewMemoryPasswordCredentialStore(), newTestPasswordResetDispatcher(t))
		servers[index] = httptest.NewServer(router)
		defer servers[index].Close()
	}
	statuses := make(chan int, 8)
	failures := make(chan error, 8)
	for index := 0; index < 8; index++ {
		go func(index int) {
			server := servers[index%2]
			response, err := server.Client().Post(server.URL+"/auth/nonce", "application/json", nil)
			if err != nil {
				failures <- err
				statuses <- 0
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		}(index)
	}
	success := 0
	for index := 0; index < 8; index++ {
		status := <-statuses
		if status == http.StatusOK {
			success++
		} else if status != http.StatusTooManyRequests {
			t.Fatalf("unexpected admission status%d", status)
		}
	}
	if success != 1 {
		t.Fatalf("successful admissions%d", success)
	}
	var count int64
	if err := first.db.Model(&nonceRecord{}).Count(&count).Error; err != nil || count != 1000 {
		t.Fatalf("stored%d error%v", count, err)
	}
}

func TestTransientRefreshQuotaPreservesRotation(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			now := time.Now().UTC()
			var store RefreshTokenStore
			if backend == "memory" {
				memory := NewMemoryRefreshTokenStore()
				for index := 0; index < refreshTenantCapacity-1; index++ {
					id := fmt.Sprint(index)
					memory.byID[id] = &memoryRecord{TokenID: id, TenantID: "tenant", ExpiresUnix: now.Add(time.Hour).Unix()}
				}
				store = memory
			} else {
				database, err := NewDatabaseRefreshTokenStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				seedApplicationSubject(t, database.db, "tenant", "user")
				records := make([]refreshTokenRecord, refreshTenantCapacity-1)
				for index := range records {
					id := fmt.Sprint(index)
					records[index] = refreshTokenRecord{TokenID: id, TokenHash: id, TenantID: "tenant", UserID: "fixture", ExpiresUnix: now.Add(time.Hour).Unix()}
				}
				if err := database.db.CreateInBatches(&records, 500).Error; err != nil {
					t.Fatal(err)
				}
				store = database
			}
			id, opaque, err := store.Issue(context.Background(), "tenant", "user", now.Add(time.Hour).Unix(), "")
			if err != nil {
				t.Fatal(err)
			}
			child, token, err := store.Issue(context.Background(), "tenant", "user", now.Add(time.Hour).Unix(), id)
			if !errors.Is(err, ErrTransientCapacity) || child != "" || token != "" {
				t.Fatalf("quota issued credentials id%s token%s error%v", child, token, err)
			}
			_, actual, _, err := store.Validate(context.Background(), "tenant", opaque)
			if err != nil || actual != id {
				t.Fatalf("quota revoked prior active token%s error%v", actual, err)
			}
		})
	}
}

func TestTransientCleanupFailureRollsBack(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	challenge, err := store.CreatePasswordSignup(context.Background(), "tenant", AccountPasswordRequest{UserEmail: "expired@example.com", Password: "correct horse battery staple"}, now.Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected cleanup failure")
	if err := store.db.Callback().Delete().Before("gorm:delete").Register("test:cleanup_failure", func(tx *gorm.DB) {
		if tx.Statement.Table == (databaseAccountChallengeRecord{}).TableName() {
			tx.AddError(injected)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpired(context.Background(), now.Add(time.Minute).Unix()); !errors.Is(err, injected) {
		t.Fatalf("cleanup failure hidden: %v", err)
	}
	if _, err := store.ResolveAccountProfile(context.Background(), "tenant", challenge.AccountID); err != nil {
		t.Fatalf("failed cleanup removed account: %v", err)
	}
	var count int64
	if err := store.db.Model(&passwordCredentialRecord{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("failed cleanup removed credential count%d error%v", count, err)
	}
}

func TestTransientRefreshMixedFamilies(t *testing.T) {
	for _, backend := range []string{"memory", "database"} {
		t.Run(backend, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			records := []refreshTokenRecord{
				{TokenID: "live-root", ExpiresUnix: now.Unix() + 3600}, {TokenID: "expired-child", PreviousTokenID: "live-root", ExpiresUnix: now.Unix() - 1},
				{TokenID: "expired-root", ExpiresUnix: now.Unix() - 1, RevokedAtUnix: now.Unix() - 10}, {TokenID: "live-child", PreviousTokenID: "expired-root", ExpiresUnix: now.Unix() + 3600}, {TokenID: "expired-branch", PreviousTokenID: "expired-root", ExpiresUnix: now.Unix() - 1},
				{TokenID: "dead-root", ExpiresUnix: now.Unix() - 1}, {TokenID: "dead-child", PreviousTokenID: "dead-root", ExpiresUnix: now.Unix() - 1},
			}
			for index := range records {
				records[index].TenantID = "tenant"
				records[index].UserID = "user"
				records[index].TokenHash = hashOpaque(records[index].TokenID)
			}
			var store RefreshTokenStore
			var cleanup interface {
				CleanupExpired(context.Context, int64) error
			}
			var rows func() int
			if backend == "memory" {
				memory := NewMemoryRefreshTokenStore()
				memory.now = func() time.Time { return now }
				for _, record := range records {
					memory.byID[record.TokenID] = &memoryRecord{TokenID: record.TokenID, TenantID: record.TenantID, UserID: record.UserID, Hash: record.TokenHash, PreviousTokenID: record.PreviousTokenID, ExpiresUnix: record.ExpiresUnix, RevokedAtUnix: record.RevokedAtUnix}
					memory.byHash[memory.hashKey(record.TenantID, record.TokenHash)] = record.TokenID
				}
				store, cleanup = memory, memory
				rows = func() int { return len(memory.byID) }
			} else {
				database, err := NewDatabaseRefreshTokenStore(context.Background(), sqliteDatabaseURL(t))
				if err != nil {
					t.Fatal(err)
				}
				database.now = func() time.Time { return now }
				if err := database.db.Create(&records).Error; err != nil {
					t.Fatal(err)
				}
				store, cleanup = database, database
				rows = func() int {
					var count int64
					if err := database.db.Model(&refreshTokenRecord{}).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					return int(count)
				}
			}
			if err := cleanup.CleanupExpired(context.Background(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if rows() != 5 {
				t.Fatalf("mixed-family rows%d want5", rows())
			}
			if _, _, _, err := store.Validate(context.Background(), "tenant", "expired-root"); !errors.Is(err, ErrRefreshTokenRevoked) {
				t.Fatalf("expired-ancestor replay%v", err)
			}
			if _, _, _, err := store.Validate(context.Background(), "tenant", "live-child"); !errors.Is(err, ErrRefreshTokenRevoked) {
				t.Fatalf("replayed family child%v", err)
			}
			now = now.Add(time.Hour)
			if err := cleanup.CleanupExpired(context.Background(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if rows() != 0 {
				t.Fatalf("last expiry retained rows%d", rows())
			}
		})
	}
}

func TestTransientRefreshCleanupQueryPlan(t *testing.T) {
	store, err := NewDatabaseRefreshTokenStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	type queryPlan struct{ Detail string }
	now := time.Now().Unix()
	var revised []queryPlan
	if err := store.db.Raw("EXPLAIN QUERY PLAN "+cleanupRefreshFamiliesSQL, now, now).Scan(&revised).Error; err != nil {
		t.Fatal(err)
	}
	for _, step := range revised {
		t.Log("revised:", step.Detail)
	}
	var probe []queryPlan
	if err := store.db.Raw("EXPLAIN QUERY PLAN SELECT token_id FROM refresh_tokens WHERE previous_token_id = '' AND expires_unix <= ? LIMIT 1", now).Scan(&probe).Error; err != nil {
		t.Fatal(err)
	}
	for _, step := range probe {
		t.Log("probe:", step.Detail)
	}
	var current []queryPlan
	oldSQL := `WITH RECURSIVE family AS (SELECT tenant_id,token_id,token_id AS root_id FROM refresh_tokens WHERE previous_token_id = '' UNION SELECT child.tenant_id,child.token_id,parent.root_id FROM refresh_tokens child JOIN family parent ON child.tenant_id=parent.tenant_id AND child.previous_token_id=parent.token_id),live_roots AS (SELECT DISTINCT family.tenant_id,family.root_id FROM family JOIN refresh_tokens token ON token.tenant_id=family.tenant_id AND token.token_id=family.token_id WHERE token.expires_unix > ?) DELETE FROM refresh_tokens WHERE (tenant_id,token_id) IN (SELECT family.tenant_id,family.token_id FROM family LEFT JOIN live_roots ON live_roots.tenant_id=family.tenant_id AND live_roots.root_id=family.root_id WHERE live_roots.root_id IS NULL)`
	if err := store.db.Raw("EXPLAIN QUERY PLAN "+oldSQL, now).Scan(&current).Error; err != nil {
		t.Fatal(err)
	}
	for _, step := range current {
		t.Log("prior:", step.Detail)
	}
}

func TestTransientSignupCleanupBatches(t *testing.T) {
	store, err := NewDatabaseUserStore(context.Background(), sqliteDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const abandonedCount = 501
	accounts := make([]databaseAccountRecord, abandonedCount+4)
	credentials := make([]passwordCredentialRecord, len(accounts))
	challenges := make([]databaseAccountChallengeRecord, len(accounts))
	for index := range accounts {
		id, err := newOpaqueAccountID()
		if err != nil {
			t.Fatal(err)
		}
		email := fmt.Sprintf("pending%d@example.com", index)
		accounts[index] = databaseAccountRecord{TenantID: "tenant", AccountID: id, UserID: id, UserEmail: email, AccountState: accountStatePendingVerification}
		credentials[index] = passwordCredentialRecord{TenantID: "tenant", UserEmail: email, UserID: id, AccountID: id, PasswordHash: "fixture"}
		challenges[index] = databaseAccountChallengeRecord{TenantID: "tenant", TokenHash: fmt.Sprint(index), AccountID: id, ChallengeKind: accountChallengeEmailVerification, ExpiresUnix: now.Unix() - 1}
	}
	accounts[abandonedCount].AccountState = accountStateActive
	if err := store.db.CreateInBatches(&accounts, 100).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.CreateInBatches(&credentials, 100).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&passwordCredentialRecord{}).Where("tenant_id = ?", "tenant").Updates(map[string]interface{}{"email_verified": false, "managed_by_config": false}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&passwordCredentialRecord{}).Where("tenant_id = ? AND account_id = ?", "tenant", accounts[abandonedCount+1].AccountID).Update("managed_by_config", true).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&passwordCredentialRecord{}).Where("tenant_id = ? AND account_id = ?", "tenant", accounts[abandonedCount+2].AccountID).Update("email_verified", true).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.CreateInBatches(&challenges, 100).Error; err != nil {
		t.Fatal(err)
	}
	replacement := databaseAccountChallengeRecord{TenantID: "tenant", TokenHash: "replacement", AccountID: accounts[abandonedCount+3].AccountID, ChallengeKind: accountChallengeEmailVerification, ExpiresUnix: now.Unix() + 3600}
	if err := store.db.Create(&replacement).Error; err != nil {
		t.Fatal(err)
	}
	var largestRead, accountDeletes, credentialDeletes int64
	if err := store.db.Callback().Query().After("gorm:query").Register("test:bounded_cleanup_read", func(tx *gorm.DB) {
		if tx.Statement.Table == (databaseAccountRecord{}).TableName() && tx.RowsAffected > largestRead {
			largestRead = tx.RowsAffected
		}
	}); err != nil {
		t.Fatal(err)
	}
	guarded := accounts[0].AccountID
	changed := false
	if err := store.db.Callback().Delete().Before("gorm:delete").Register("test:bounded_cleanup_delete", func(tx *gorm.DB) {
		switch tx.Statement.Table {
		case (databaseAccountRecord{}).TableName():
			accountDeletes++
			if !changed {
				changed = true
				tx.AddError(tx.Session(&gorm.Session{NewDB: true}).Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ?", "tenant", guarded).Update("account_state", accountStateActive).Error)
			}
		case passwordCredentialTableName:
			credentialDeletes++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpired(context.Background(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	if largestRead > 250 {
		t.Fatalf("cleanup read%d abandoned accounts at once; bound250", largestRead)
	}
	if accountDeletes > 3 || credentialDeletes > 3 {
		t.Fatalf("cleanup used%d account and%d credential statements; want at most3 each", accountDeletes, credentialDeletes)
	}
	var count int64
	for _, model := range []interface{}{&databaseAccountRecord{}, &passwordCredentialRecord{}} {
		if err := store.db.Model(model).Count(&count).Error; err != nil || count != 5 {
			t.Fatalf("preserved rows%d error%v", count, err)
		}
	}
	if err := store.db.Model(&databaseAccountChallengeRecord{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("live replacement rows%d error%v", count, err)
	}
	if _, err := store.ResolveAccountProfile(context.Background(), "tenant", guarded); err != nil {
		t.Fatalf("account that failed pending deletion guard removed: %v", err)
	}
}
