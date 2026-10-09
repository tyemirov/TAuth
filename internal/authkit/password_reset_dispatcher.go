package authkit

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"sync"
	"sync/atomic"
	"time"
)

const (
	passwordResetQueueCapacity  = 256
	passwordResetSourceCapacity = 8
	passwordResetTenantCapacity = 64
	passwordResetJobTimeout     = 30 * time.Second
	passwordResetCleanupTimeout = 5 * time.Second
)

type passwordResetJob struct {
	tenantID, email, source string
	resetURL                string
	resetTTL                time.Duration
	emailDeliveryEnabled    bool
	store                   AccountManagementStore
	sender                  EmailChallengeSender
	clock                   Clock
}

// PasswordResetDispatcher owns bounded recovery work independently of HTTP requests.
type PasswordResetDispatcher struct {
	ctx         context.Context
	cancel      context.CancelFunc
	jobs        chan passwordResetJob
	done        chan struct{}
	mu          sync.Mutex
	closed      bool
	outstanding int
	sources     map[string]int
	tenants     map[string]int
	pending     map[string]struct{}
	rejected    atomic.Uint64
	coalesced   atomic.Uint64
}

// NewPasswordResetDispatcher starts recovery work under the service lifecycle.
func NewPasswordResetDispatcher(ctx context.Context) (*PasswordResetDispatcher, error) {
	if ctx == nil {
		return nil, errors.New("password reset dispatcher requires service context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	dispatcher := &PasswordResetDispatcher{ctx: serviceCtx, cancel: cancel, jobs: make(chan passwordResetJob, passwordResetQueueCapacity), done: make(chan struct{}), sources: make(map[string]int), tenants: make(map[string]int), pending: make(map[string]struct{})}
	go dispatcher.run()
	return dispatcher, nil
}

// Close stops admission, cancels active work, discards queued work, and joins the worker.
func (dispatcher *PasswordResetDispatcher) Close() {
	dispatcher.mu.Lock()
	dispatcher.closed = true
	dispatcher.cancel()
	dispatcher.mu.Unlock()
	<-dispatcher.done
}

func (dispatcher *PasswordResetDispatcher) enqueue(job passwordResetJob) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	key := job.tenantID + "\x00" + job.email
	if dispatcher.closed || dispatcher.ctx.Err() != nil {
		dispatcher.rejected.Add(1)
		return
	}
	if _, exists := dispatcher.pending[key]; exists {
		dispatcher.coalesced.Add(1)
		return
	}
	if dispatcher.outstanding >= passwordResetQueueCapacity || dispatcher.sources[job.source] >= passwordResetSourceCapacity || dispatcher.tenants[job.tenantID] >= passwordResetTenantCapacity {
		dispatcher.rejected.Add(1)
		return
	}
	dispatcher.pending[key] = struct{}{}
	dispatcher.outstanding++
	dispatcher.sources[job.source]++
	dispatcher.tenants[job.tenantID]++
	dispatcher.jobs <- job
}

func (dispatcher *PasswordResetDispatcher) finish(job passwordResetJob) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	delete(dispatcher.pending, job.tenantID+"\x00"+job.email)
	dispatcher.outstanding--
	dispatcher.sources[job.source]--
	if dispatcher.sources[job.source] == 0 {
		delete(dispatcher.sources, job.source)
	}
	dispatcher.tenants[job.tenantID]--
	if dispatcher.tenants[job.tenantID] == 0 {
		delete(dispatcher.tenants, job.tenantID)
	}
}

func (dispatcher *PasswordResetDispatcher) run() {
	defer close(dispatcher.done)
	defer dispatcher.logAdmission()
	for {
		select {
		case <-dispatcher.ctx.Done():
			for {
				select {
				case job := <-dispatcher.jobs:
					dispatcher.finish(job)
				default:
					return
				}
			}
		case job := <-dispatcher.jobs:
			if dispatcher.ctx.Err() == nil {
				dispatcher.execute(job)
			}
			dispatcher.finish(job)
			dispatcher.logAdmission()
		}
	}
}

func (dispatcher *PasswordResetDispatcher) execute(job passwordResetJob) {
	ctx, cancel := context.WithTimeout(dispatcher.ctx, passwordResetJobTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, requestSourceKey{}, job.source)
	expiry := job.clock.Now().UTC().Add(effectiveDuration(job.resetTTL, 15*time.Minute))
	challenge, err := job.store.StartPasswordReset(ctx, job.tenantID, job.email, expiry.Unix())
	if err != nil {
		if !errors.Is(err, ErrAccountNotFound) && !errors.Is(err, ErrPasswordCredentialInvalid) && !errors.Is(err, ErrAuthenticationRateLimited) {
			logAuthError("auth.account.reset_start", resetBoundaryError("storage", err))
		}
		return
	}
	if !job.emailDeliveryEnabled || job.sender == nil {
		dispatcher.cleanup(job, challenge)
		return
	}
	publicURL, err := buildEmailChallengeURL(job.resetURL, challenge.Token)
	if err == nil {
		err = job.sender.SendEmailChallenge(ctx, EmailChallengeRequest{Kind: EmailChallengeKindPasswordReset, TenantID: job.tenantID, Recipient: job.email, PublicURL: publicURL, ExpiresAt: expiry})
	}
	if err != nil {
		dispatcher.cleanup(job, challenge)
		logAuthError("auth.account.password_reset_delivery", resetBoundaryError("delivery", err))
	}
}

func (dispatcher *PasswordResetDispatcher) cleanup(job passwordResetJob, challenge AccountChallenge) {
	ctx, cancel := context.WithTimeout(context.Background(), passwordResetCleanupTimeout)
	defer cancel()
	if err := job.store.CancelAccountChallenge(ctx, job.tenantID, challenge.AccountID, challenge.Token); err != nil {
		logAuthError("auth.account.challenge_cancel", resetBoundaryError("cleanup", err))
	}
}

func (dispatcher *PasswordResetDispatcher) logAdmission() {
	rejected := dispatcher.rejected.Swap(0)
	coalesced := dispatcher.coalesced.Swap(0)
	if rejected+coalesced > 0 {
		logAuthWarning("auth.account.reset_admission", nil, zap.Uint64("rejected", rejected), zap.Uint64("coalesced", coalesced))
	}
}

func resetBoundaryError(operation string, err error) error {
	cause := errors.New("boundary operation failed")
	for _, category := range []error{context.Canceled, context.DeadlineExceeded, ErrTransientCapacity} {
		if errors.Is(err, category) {
			cause = category
			break
		}
	}
	return fmt.Errorf("password reset %s: %w", operation, cause)
}
