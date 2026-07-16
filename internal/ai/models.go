package ai

// ChatMessage is one turn of the conversation (role: "user" | "assistant").
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the payload for POST /api/v1/ai/chat.
type ChatRequest struct {
	Message string        `json:"message" binding:"required"`
	History []ChatMessage `json:"history"`
	Context string        `json:"context"` // optional: what the analyst is currently viewing
}

// ChatResponse is returned to the client. Source identifies which backend
// answered: "local:<model>", "claude", or "simulated".
type ChatResponse struct {
	Reply  string `json:"reply"`
	Source string `json:"source"`
}

// Config carries the resolved AI settings from the app config.
type Config struct {
	Provider        string // auto | local | claude | off
	OllamaURL       string
	OllamaModel     string
	AnthropicAPIKey string
	AnthropicModel  string
}
