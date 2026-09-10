package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry ek single audit record hai
type Entry struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	Comm        string `json:"comm"`
	Detail      string `json:"detail"`
	PID         uint32 `json:"pid"`
	ThreatScore int    `json:"threat_score,omitempty"`
	Tier        string `json:"tier"`
	Reason      string `json:"reason"`
	ActionTaken string `json:"action_taken,omitempty"`
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
}

// Logger append-only, hash-chained audit log likhta hai
type Logger struct {
	mu       sync.Mutex
	filePath string
	lastHash string
}

func NewLogger(filePath string) (*Logger, error) {
	l := &Logger{filePath: filePath, lastHash: "genesis"}
	l.loadLastHash()
	return l, nil
}

// loadLastHash file ki aakhri line padhke uska hash nikalta hai,
// taaki restart ke baad bhi chain continue rahe (naye genesis se shuru na ho)
func (l *Logger) loadLastHash() {
	data, err := os.ReadFile(l.filePath)
	if err != nil || len(data) == 0 {
		return
	}

	var lastLine []byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lastLine = data[start:i]
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lastLine = data[start:]
	}

	if len(lastLine) == 0 {
		return
	}

	var e Entry
	if err := json.Unmarshal(lastLine, &e); err == nil && e.Hash != "" {
		l.lastHash = e.Hash
	}
}

// Log ek naya entry likhta hai, chain mein pichle hash ke saath linked
func (l *Logger) Log(eventType, comm, detail string, pid uint32, threatScore int, tier, reason, actionTaken string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		EventType:   eventType,
		Comm:        comm,
		Detail:      detail,
		PID:         pid,
		ThreatScore: threatScore,
		Tier:        tier,
		Reason:      reason,
		ActionTaken: actionTaken,
		PrevHash:    l.lastHash,
	}

	// Hash calculate karo (sab fields + prev_hash ka, taaki tampering detect ho sake)
	e.Hash = computeHash(e)
	l.lastHash = e.Hash

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	_, err = f.Write(append(line, '\n'))
	return err
}

func computeHash(e Entry) string {
	// Hash field ko khud shamil na karo (chicken-egg problem)
	raw := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s|%s|%s|%s",
		e.Timestamp, e.EventType, e.Comm, e.Detail, e.PID, e.ThreatScore, e.Tier, e.Reason, e.ActionTaken, e.PrevHash)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// VerifyChain poori audit log file ko verify karta hai — tamper-evidence check
func VerifyChain(filePath string) (bool, int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, 0, err
	}

	lines := splitLines(data)
	prevHash := "genesis"
	count := 0

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return false, count, fmt.Errorf("malformed entry at line %d: %w", count+1, err)
		}

		if e.PrevHash != prevHash {
			return false, count, fmt.Errorf("chain broken at line %d: expected prev_hash %s, got %s", count+1, prevHash, e.PrevHash)
		}

		expectedHash := computeHash(Entry{
			Timestamp: e.Timestamp, EventType: e.EventType, Comm: e.Comm, Detail: e.Detail,
			PID: e.PID, ThreatScore: e.ThreatScore, Tier: e.Tier, Reason: e.Reason,
			ActionTaken: e.ActionTaken, PrevHash: e.PrevHash,
		})
		if expectedHash != e.Hash {
			return false, count, fmt.Errorf("hash mismatch at line %d: possible tampering", count+1)
		}

		prevHash = e.Hash
		count++
	}

	return true, count, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
