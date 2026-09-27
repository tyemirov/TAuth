package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

const ConsoleTenantID = "tauth-console"
const InitialOwnerEmail = "vtyemirov@gmail.com"

var ErrEnrollment = errors.New("management.enrollment_denied")

// Owner is the public owner account representation.
type Owner struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	DisplayName  string    `json:"display_name" gorm:"not null"`
	ContactEmail string    `json:"contact_email" gorm:"not null"`
	State        string    `json:"state" gorm:"not null;check:state = 'active'"`
	CreatedAt    time.Time `json:"created_at"`
}

func (Owner) TableName() string { return "owner_accounts" }

type ownerBinding struct {
	Issuer          string `gorm:"primaryKey"`
	ConsoleTenantID string `gorm:"primaryKey"`
	Subject         string `gorm:"primaryKey"`
	OwnerAccountID  string `gorm:"not null;uniqueIndex"`
	Owner           Owner  `gorm:"foreignKey:OwnerAccountID;references:ID;constraint:OnDelete:RESTRICT"`
}

func (ownerBinding) TableName() string { return "owner_login_bindings" }

type consoleBootstrap struct {
	ID             string `gorm:"primaryKey"`
	Configuration  []byte `gorm:"not null"`
	Digest         string `gorm:"not null"`
	InitialOwnerID *string
	InitialOwner   *Owner `gorm:"foreignKey:InitialOwnerID;references:ID;constraint:OnDelete:RESTRICT"`
}

// Store holds persistent control plane data and its authenticated cipher.
type Store struct {
	db        *gorm.DB
	cipher    cipher.AEAD
	keyID     string
	digestKey []byte
}

// Open validates the service encryption key and initializes the database.
func Open(ctx context.Context, databaseURL, encodedKey string) (*Store, error) {
	store, err := connect(ctx, databaseURL, encodedKey, []interface{}{&Owner{}, &ownerBinding{}, &consoleBootstrap{}})
	if err != nil {
		return nil, err
	}
	if err := initializeTenantSchema(ctx, store.db); err != nil {
		return nil, err
	}
	return store, nil
}

// OpenExisting connects without schema changes for diagnostic reads.
func OpenExisting(ctx context.Context, databaseURL, encodedKey string) (*Store, error) {
	return connect(ctx, databaseURL, encodedKey, nil)
}

func connect(ctx context.Context, databaseURL, encodedKey string, models []interface{}) (*Store, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("management.encryption_key: require base64 encoded 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("management.cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("management.cipher: %w", err)
	}
	db, err := authkit.OpenControlDatabase(ctx, databaseURL, models...)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, cipher: aead, keyID: fmt.Sprintf("%x", sha256.Sum256(key)), digestKey: key}, nil
}

// Close releases the database connection.
func (store *Store) Close() error {
	db, err := store.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

func (store *Store) seal(value []byte, binding string) []byte {
	nonce := make([]byte, store.cipher.NonceSize())
	_, _ = rand.Read(nonce)
	return store.cipher.Seal(nonce, nonce, value, []byte(binding))
}
func (store *Store) unseal(value []byte, binding string) ([]byte, error) {
	size := store.cipher.NonceSize()
	if len(value) < size {
		return nil, errors.New("management.ciphertext_invalid")
	}
	plaintext, err := store.cipher.Open(nil, value[:size], value[size:], []byte(binding))
	if err != nil {
		return nil, fmt.Errorf("management.decrypt: %w", err)
	}
	return plaintext, nil
}

// Bootstrap installs the reserved console configuration exactly once.
func (store *Store) Bootstrap(ctx context.Context, file tenants.FileTenant) error {
	document, err := tenants.ResolveDocument(tenants.FileDocument{Tenants: []tenants.FileTenant{file}})
	if err != nil {
		return err
	}
	file = document.Tenants[0]
	if file.ID != ConsoleTenantID || len(file.TenantOrigins) != 1 || file.GoogleWebClientID == "" || !bool(file.AccountManagement.Enabled) || bool(file.AccountManagement.ReturnChallengeTokens) || bool(file.PasswordAuth.Enabled) || bool(file.AccountManagement.PasswordSignup.Enabled) || bool(file.AppleOAuth.Enabled) || bool(file.GitHubOAuth.Enabled) || file.GoogleNativeClientID != "" || len(file.GoogleNativeClients) > 0 || file.AllowedUsers != nil || file.CookieDomain != "" || file.SessionCookieName != "tauth_console_session" || file.RefreshCookieName != "tauth_console_refresh" {
		return errors.New("management.console_configuration_invalid")
	}
	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("management.encode_console: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing consoleBootstrap
		err := tx.First(&existing, "id = ?", ConsoleTenantID).Error
		if err == nil {
			if existing.Digest != digest {
				return errors.New("management.bootstrap_conflict")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("management.read_bootstrap: %w", err)
		}
		if err := tx.Create(&consoleBootstrap{ID: ConsoleTenantID, Configuration: store.seal(data, ConsoleTenantID), Digest: digest}).Error; err != nil {
			return fmt.Errorf("management.create_bootstrap: %w", err)
		}
		return nil
	})
}

// Console loads and decrypts the operator-owned console configuration.
func (store *Store) Console(ctx context.Context) (tenants.FileTenant, error) {
	var record consoleBootstrap
	if err := store.db.WithContext(ctx).First(&record, "id = ?", ConsoleTenantID).Error; err != nil {
		return tenants.FileTenant{}, fmt.Errorf("management.read_console: %w", err)
	}
	data, err := store.unseal(record.Configuration, ConsoleTenantID)
	if err != nil {
		return tenants.FileTenant{}, err
	}
	var file tenants.FileTenant
	if err := json.Unmarshal(data, &file); err != nil {
		return file, fmt.Errorf("management.decode_console: %w", err)
	}
	return file, nil
}

func newID() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	return base64.RawURLEncoding.EncodeToString(value)
}

// OwnerForSubject reads the stable console binding.
func (store *Store) OwnerForSubject(ctx context.Context, issuer, subject string) (Owner, error) {
	var binding ownerBinding
	err := store.db.WithContext(ctx).Preload("Owner").First(&binding, "issuer = ? AND console_tenant_id = ? AND subject = ?", issuer, ConsoleTenantID, subject).Error
	return binding.Owner, err
}

// Provision binds a verified console subject to one persistent owner account.
func (store *Store) Provision(ctx context.Context, issuer, subject, email, display string) (Owner, bool, error) {
	var owner Owner
	created := false
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize enrollment and retry decisions through the singleton bootstrap row.
		if err := tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Update("id", ConsoleTenantID).Error; err != nil {
			return err
		}
		var bootstrap consoleBootstrap
		if err := tx.First(&bootstrap, "id = ?", ConsoleTenantID).Error; err != nil {
			return err
		}
		local := &Store{db: tx, cipher: store.cipher}
		existing, err := local.OwnerForSubject(ctx, issuer, subject)
		if err == nil {
			owner = existing
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		initialEmail := strings.EqualFold(email, InitialOwnerEmail)
		if (bootstrap.InitialOwnerID == nil && !initialEmail) || (bootstrap.InitialOwnerID != nil && initialEmail) {
			return ErrEnrollment
		}
		owner = Owner{ID: newID(), DisplayName: display, ContactEmail: email, State: "active", CreatedAt: time.Now().UTC()}
		if err := tx.Create(&owner).Error; err != nil {
			return err
		}
		if err := tx.Create(&ownerBinding{Issuer: issuer, ConsoleTenantID: ConsoleTenantID, Subject: subject, OwnerAccountID: owner.ID}).Error; err != nil {
			return err
		}
		if bootstrap.InitialOwnerID == nil {
			if err := tx.Model(&bootstrap).Update("initial_owner_id", owner.ID).Error; err != nil {
				return err
			}
		}
		created = true
		return nil
	})
	if err != nil {
		return Owner{}, false, fmt.Errorf("management.provision_owner: %w", err)
	}
	return owner, created, nil
}
