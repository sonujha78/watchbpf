package policy

import (
	"fmt"
	"sync"
	"time"
)

// Tier represents ek response level
type Tier string

const (
	TierLog    Tier = "log"
	TierAlert  Tier = "alert"
	TierSoft   Tier = "soft_action"
	TierHard   Tier = "hard_action"
)

// Decision policy engine ka final output hai
type Decision struct {
	Tier   Tier
	Reason string
}

// Engine tiered thresholds, protected-process list, aur rate-limiting apply karta hai
type Engine struct {
	mu sync.Mutex

	// Config
	enforceMode string // "dry-run" | "live"
	protectedComms map[string]bool

	// Rate limiting
	actionWindow  time.Duration
	maxActionsPerWindow int
	actionTimestamps []time.Time

	thresholdAlert int
	thresholdSoft  int
	thresholdHard  int
}

// NewEngine, config ke thresholds/protected-list/rate-limit ke saath policy engine banata hai
func NewEngine(enforceMode string, protectedList []string, maxActionsPerWindow int, thresholdAlert, thresholdSoft, thresholdHard int) *Engine {
	protectedMap := make(map[string]bool)
	for _, p := range protectedList {
		protectedMap[p] = true
	}

	return &Engine{
		enforceMode:         enforceMode,
		protectedComms:      protectedMap,
		actionWindow:        1 * time.Minute,
		maxActionsPerWindow: maxActionsPerWindow,
		thresholdAlert:      thresholdAlert,
		thresholdSoft:       thresholdSoft,
		thresholdHard:       thresholdHard,
	}
}

// Evaluate ek threat score ko tiered decision mein convert karta hai
func (e *Engine) Evaluate(comm string, score int) Decision {
	var tier Tier
	switch {
	case score >= e.thresholdHard:
		tier = TierHard
	case score >= e.thresholdSoft:
		tier = TierSoft
	case score >= e.thresholdAlert:
		tier = TierAlert
	default:
		tier = TierLog
	}

	// Guardrail 1: protected process — kabhi hard/soft action nahi, max alert
	if e.protectedComms[comm] {
		if tier == TierHard || tier == TierSoft {
			return Decision{Tier: TierAlert, Reason: fmt.Sprintf("process %q is on protected list — downgraded from %s to alert", comm, tier)}
		}
	}

	// Guardrail 2: dry-run mode — kabhi actual action nahi, sirf report karo kya hota
	if e.enforceMode != "live" && (tier == TierHard || tier == TierSoft) {
		return Decision{Tier: tier, Reason: "DRY-RUN: would have taken this action, but enforcement is not live"}
	}

	// Guardrail 3: rate limiting — agar limit cross ho gayi to hard/soft actions ko alert mein downgrade karo
	if tier == TierHard || tier == TierSoft {
		if !e.allowAction() {
			return Decision{Tier: TierAlert, Reason: "rate limit exceeded — downgraded to alert to prevent action storm"}
		}
	}

	return Decision{Tier: tier, Reason: "threshold-based decision"}
}

// allowAction sliding-window rate limit check karta hai
func (e *Engine) allowAction() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-e.actionWindow)

	// Purani timestamps hatao
	filtered := e.actionTimestamps[:0]
	for _, t := range e.actionTimestamps {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	e.actionTimestamps = filtered

	if len(e.actionTimestamps) >= e.maxActionsPerWindow {
		return false
	}

	e.actionTimestamps = append(e.actionTimestamps, now)
	return true
}
