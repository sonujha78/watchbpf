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

type GeminiClient struct {
	apiKey string
	model  string
	prompt string
}

// NewGeminiClient nil return karta hai agar koi API key na mile —
// caller ko fallback (Ollama) pe switch karna chahiye
func NewGeminiClient(promptTemplate string) *GeminiClient {
	key := os.Getenv("WATCHBPF_GEMINI_API_KEY")

	// Fallback: agar env var na mile (jaise sudo ke andar), config file se padho
	if key == "" {
		if data, err := os.ReadFile("/etc/watchbpf/gemini.key"); err == nil {
			key = strings.TrimSpace(string(data))
		}
	}

	if key == "" {
		return nil
	}
	return &GeminiClient{apiKey: key, model: "gemini-flash-latest", prompt: promptTemplate}
}

func (c *GeminiClient) Name() string { return "gemini:" + c.model }

type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}
type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}
type geminiPart struct {
	Text string `json:"text"`
}
type geminiResponse struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
}

func (c *GeminiClient) Assess(ctx context.Context, story EventStory) (*ThreatAssessment, error) {
	fullPrompt := fmt.Sprintf(c.prompt, story.EventType, story.Comm, story.Detail, story.PID, story.UID)

	reqBody := geminiRequest{
		Contents: []geminiContent{{Parts: []geminiPart{{Text: fullPrompt}}}},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.model, c.apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini API error (status %d): %s", resp.StatusCode, string(body))
	}

	var gr geminiResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return nil, fmt.Errorf("parsing gemini envelope: %w", err)
	}
	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini returned no candidates")
	}

	return parseAssessment(gr.Candidates[0].Content.Parts[0].Text)
}
