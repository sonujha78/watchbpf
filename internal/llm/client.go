package llm

import "context"

// ThreatAssessment LLM se aane wala strict-schema response hai
type ThreatAssessment struct {
	ThreatScore  int    `json:"threat_score"`  // 0-100
	Label        string `json:"label"`         // e.g. "benign", "suspicious", "malicious"
	MitreTactic  string `json:"mitre_tactic"`  // e.g. "Execution", "Discovery", "none"
	Confidence   int    `json:"confidence"`    // 0-100
	Action       string `json:"recommended_action"` // "log" | "alert" | "isolate" | "kill"
	Rationale    string `json:"rationale"`     // short human-readable reason
}

// EventStory ek escalated event ka context hai jo LLM ko bheja jaata hai
type EventStory struct {
	EventType string `json:"event_type"` // EXEC, OPEN, CONNECT
	Comm      string `json:"comm"`
	Detail    string `json:"detail"` // filename ya ip:port
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
}

// Client har LLM backend (Gemini, Ollama) ko implement karna hoga
type Client interface {
	Assess(ctx context.Context, story EventStory) (*ThreatAssessment, error)
	Name() string
}
