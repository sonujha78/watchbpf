package baseline

import (
	"encoding/json"
	"os"
	"sync"
)

// Store ek thread-safe, disk-persisted allowlist hai.
// Key format: "<eventType>|<comm>|<path>" — e.g. "EXEC|ls|/bin/ls"
type Store struct {
	mu       sync.RWMutex
	known    map[string]bool
	filePath string
}

func NewStore(filePath string) *Store {
	s := &Store{
		known:    make(map[string]bool),
		filePath: filePath,
	}
	s.load()
	return s
}

func makeKey(eventType, comm, path string) string {
	return eventType + "|" + comm + "|" + path
}

// IsKnown check karta hai ki ye combination pehle dekha gaya hai ya nahi
func (s *Store) IsKnown(eventType, comm, path string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.known[makeKey(eventType, comm, path)]
}

// Learn ek naya combination allowlist mein add karta hai
func (s *Store) Learn(eventType, comm, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.known[makeKey(eventType, comm, path)] = true
}

// Count total learned entries return karta hai
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.known)
}

// Save current allowlist ko disk pe JSON format mein likhta hai
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.known))
	for k := range s.known {
		keys = append(keys, k)
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0644)
}

// load disk se existing allowlist padhta hai agar file exist karti hai
func (s *Store) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return // file na ho to khaali state se shuru karo, error nahi
	}

	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		s.known[k] = true
	}
}
