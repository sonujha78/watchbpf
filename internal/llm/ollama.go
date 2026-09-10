package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type OllamaClient struct {
	baseURL string
	model   string
	prompt  string
}

func NewOllamaClient(promptTemplate string) *OllamaClient {
	base := os.Getenv("WATCHBPF_OLLAMA_URL")
	if base == "" {
		base = "http://localhost:11434"
	}
	model := os.Getenv("WATCHBPF_OLLAMA_MODEL")
	if model == "" {
		model = "llama3.1:8b"
	}
	return &OllamaClient{baseURL: base, model: model, prompt: promptTemplate}
}

func (c *OllamaClient) Name() string { return "ollama:" + c.model }

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	Format string `json:"format"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

func (c *OllamaClient) Assess(ctx context.Context, story EventStory) (*ThreatAssessment, error) {
	fullPrompt := fmt.Sprintf(c.prompt, story.EventType, story.Comm, story.Detail, story.PID, story.UID)

	reqBody := ollamaRequest{
		Model:  c.model,
		Prompt: fullPrompt,
		Stream: false,
		Format: "json",
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/generate", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed (is ollama running? try: ollama serve): %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var or ollamaResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return nil, fmt.Errorf("parsing ollama envelope: %w", err)
	}

	return parseAssessment(or.Response)
}

// parseAssessment LLM ke raw text output ko strict struct mein convert karta hai,
// aur agar schema off ho to safely reject karta hai (kabhi crash nahi, kabhi blind-trust nahi)
func parseAssessment(raw string) (*ThreatAssessment, error) {
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")

	var ta ThreatAssessment
	if err := json.Unmarshal([]byte(cleaned), &ta); err != nil {
		return nil, fmt.Errorf("LLM response not valid JSON schema: %w (raw: %s)", err, cleaned)
	}

	// Server-side validation — kabhi LLM ke output ko blindly trust nahi karna
	if ta.ThreatScore < 0 || ta.ThreatScore > 100 {
		return nil, fmt.Errorf("invalid threat_score: %d", ta.ThreatScore)
	}
	validActions := map[string]bool{"log": true, "alert": true, "isolate": true, "kill": true}
	if !validActions[ta.Action] {
		return nil, fmt.Errorf("invalid recommended_action: %q", ta.Action)
	}

	return &ta, nil
}
