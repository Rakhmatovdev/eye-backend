// Package ai provides a multi-provider AI analyst assistant. It grounds replies
// in a live snapshot of the platform's data (entities, threats, incidents, …)
// and answers via a LOCAL model (Ollama), the Anthropic Claude API, or a
// deterministic simulated fallback — whichever is available. All platform data
// is synthetic demo data.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const (
	anthropicURL     = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
)

type Service struct {
	db     *mongo.Database
	log    *zap.Logger
	cfg    Config
	client *http.Client
}

func NewService(db *mongo.Database, log *zap.Logger, cfg Config) *Service {
	return &Service{db: db, log: log, cfg: cfg, client: &http.Client{Timeout: 90 * time.Second}}
}

// Chat answers a user message, grounded in a live platform snapshot. It picks a
// provider based on config and availability, falling back gracefully.
func (s *Service) Chat(ctx context.Context, req ChatRequest) ChatResponse {
	system := s.systemPrompt(ctx, req.Context)

	// Assemble the running conversation.
	msgs := make([]ChatMessage, 0, len(req.History)+1)
	for _, h := range req.History {
		if h.Role == "user" || h.Role == "assistant" {
			msgs = append(msgs, h)
		}
	}
	msgs = append(msgs, ChatMessage{Role: "user", Content: req.Message})

	provider := s.cfg.Provider
	if provider == "" {
		provider = "auto"
	}

	tryLocal := provider == "auto" || provider == "local"
	tryClaude := provider == "auto" || provider == "claude"

	if tryLocal && s.cfg.OllamaURL != "" {
		if reply, err := s.callOllama(ctx, system, msgs); err == nil && strings.TrimSpace(reply) != "" {
			return ChatResponse{Reply: reply, Source: "local:" + s.cfg.OllamaModel}
		} else if err != nil {
			s.log.Debug("ollama unavailable, falling back", zap.Error(err))
		}
	}

	if tryClaude && s.cfg.AnthropicAPIKey != "" {
		if reply, err := s.callClaude(ctx, system, msgs); err == nil && strings.TrimSpace(reply) != "" {
			return ChatResponse{Reply: reply, Source: "claude"}
		} else if err != nil {
			s.log.Warn("claude call failed, falling back", zap.Error(err))
		}
	}

	return ChatResponse{Reply: s.simulatedReply(ctx, req.Message), Source: "simulated"}
}

func (s *Service) chats() *mongo.Collection { return s.db.Collection("ai_chats") }

// SaveChat persists one chat exchange to the `ai_chats` collection. It is
// best-effort: a failure is logged but never returned to the caller, so a
// storage hiccup never fails the already-answered chat response.
func (s *Service) SaveChat(ctx context.Context, userID, message, reply, source string) {
	if userID == "" {
		userID = "anonymous"
	}
	doc := ChatHistoryEntry{
		ID:        uuid.New().String(),
		UserID:    userID,
		Message:   message,
		Reply:     reply,
		Source:    source,
		Timestamp: time.Now(),
	}
	if _, err := s.chats().InsertOne(ctx, doc); err != nil {
		s.log.Error("failed to persist ai chat exchange", zap.Error(err))
	}
}

// History returns the current user's most recent chat exchanges, oldest
// first, capped at limit (default/invalid -> 50, max 200).
func (s *Service) History(ctx context.Context, userID string, limit int) ([]*ChatHistoryEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	opts := options.Find().SetSort(bson.D{{Key: "ts", Value: -1}}).SetLimit(int64(limit))
	cur, err := s.chats().Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	list := []*ChatHistoryEntry{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	// Reverse the (newest-first) query result to oldest-first for the client.
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	return list, nil
}

/* ------------------------------ Ollama (local) --------------------------- */

type ollamaReq struct {
	Model    string        `json:"model"`
	Messages []ollamaMsg   `json:"messages"`
	Stream   bool          `json:"stream"`
	Options  ollamaOptions `json:"options"`
}
type ollamaMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
}
type ollamaResp struct {
	Message ollamaMsg `json:"message"`
	Error   string    `json:"error"`
}

func (s *Service) callOllama(ctx context.Context, system string, msgs []ChatMessage) (string, error) {
	om := make([]ollamaMsg, 0, len(msgs)+1)
	om = append(om, ollamaMsg{Role: "system", Content: system})
	for _, m := range msgs {
		om = append(om, ollamaMsg{Role: m.Role, Content: m.Content})
	}
	body, _ := json.Marshal(ollamaReq{Model: s.cfg.OllamaModel, Messages: om, Stream: false, Options: ollamaOptions{Temperature: 0.4}})

	// Short timeout so an absent Ollama fails fast and we can fall back.
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, strings.TrimRight(s.cfg.OllamaURL, "/")+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama %d: %s", resp.StatusCode, string(data))
	}
	var or ollamaResp
	if err := json.Unmarshal(data, &or); err != nil {
		return "", err
	}
	if or.Error != "" {
		return "", fmt.Errorf("ollama: %s", or.Error)
	}
	return or.Message.Content, nil
}

/* ------------------------------ Anthropic Claude ------------------------- */

type anthropicReq struct {
	Model     string         `json:"model"`
	MaxTokens int            `json:"max_tokens"`
	System    string         `json:"system,omitempty"`
	Messages  []anthropicMsg `json:"messages"`
}
type anthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type anthropicResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (s *Service) callClaude(ctx context.Context, system string, msgs []ChatMessage) (string, error) {
	am := make([]anthropicMsg, 0, len(msgs))
	for _, m := range msgs {
		am = append(am, anthropicMsg{Role: m.Role, Content: m.Content})
	}
	body, _ := json.Marshal(anthropicReq{Model: s.cfg.AnthropicModel, MaxTokens: 1024, System: system, Messages: am})

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", s.cfg.AnthropicAPIKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(data))
	}
	var ar anthropicResp
	if err := json.Unmarshal(data, &ar); err != nil {
		return "", err
	}
	if ar.StopReason == "refusal" {
		return "", fmt.Errorf("request refused by safety policy")
	}
	var sb strings.Builder
	for _, b := range ar.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	return sb.String(), nil
}

/* ------------------------------ Grounding / snapshot --------------------- */

type snapshot struct {
	Entities        int64
	Sensors         int64
	Threats         int64
	CriticalThreats int64
	OpenIncidents   int64
	ActiveMissions  int64
	TopThreats      []string
	OpenIncidentTit []string
}

func (s *Service) gather(ctx context.Context) snapshot {
	var sn snapshot
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sn.Entities, _ = s.db.Collection("entities").CountDocuments(ctx, bson.M{})
	sn.Sensors, _ = s.db.Collection("sensors").CountDocuments(ctx, bson.M{})
	sn.Threats, _ = s.db.Collection("mil_threats").CountDocuments(ctx, bson.M{})
	sn.CriticalThreats, _ = s.db.Collection("mil_threats").CountDocuments(ctx, bson.M{"threat_level": "critical"})
	sn.OpenIncidents, _ = s.db.Collection("security_incidents").CountDocuments(ctx, bson.M{"status": bson.M{"$in": bson.A{"open", "investigating"}}})
	sn.ActiveMissions, _ = s.db.Collection("mil_missions").CountDocuments(ctx, bson.M{"status": "active"})

	if cur, err := s.db.Collection("mil_threats").Find(ctx, bson.M{}, options.Find().SetLimit(6)); err == nil {
		var rows []struct {
			Designation string `bson:"designation"`
			Level       string `bson:"threat_level"`
		}
		_ = cur.All(ctx, &rows)
		for _, r := range rows {
			sn.TopThreats = append(sn.TopThreats, fmt.Sprintf("%s [%s]", r.Designation, r.Level))
		}
	}
	if cur, err := s.db.Collection("security_incidents").Find(ctx, bson.M{"status": bson.M{"$in": bson.A{"open", "investigating"}}}, options.Find().SetLimit(6)); err == nil {
		var rows []struct {
			Title    string `bson:"title"`
			Severity string `bson:"severity"`
		}
		_ = cur.All(ctx, &rows)
		for _, r := range rows {
			sn.OpenIncidentTit = append(sn.OpenIncidentTit, fmt.Sprintf("%s (%s)", r.Title, r.Severity))
		}
	}
	return sn
}

func (s *Service) systemPrompt(ctx context.Context, viewing string) string {
	sn := s.gather(ctx)
	var b strings.Builder
	b.WriteString("You are the AI analyst assistant for \"Ko'z\", a Palantir-style intelligence and defense platform. ")
	b.WriteString("You help analysts interpret entities, surveillance detections, security incidents, and the military common operating picture (units, threats, missions). ")
	b.WriteString("Answer concisely and operationally, like an intelligence analyst. Ground your answers in the LIVE SNAPSHOT below; if something isn't in the data, say so plainly. This is a demo environment with synthetic data — do not claim access to real-world systems.\n\n")
	b.WriteString("LIVE SNAPSHOT:\n")
	fmt.Fprintf(&b, "- Entities in graph: %d\n- Surveillance sensors: %d\n- Threat tracks: %d (critical: %d)\n- Open security incidents: %d\n- Active missions: %d\n",
		sn.Entities, sn.Sensors, sn.Threats, sn.CriticalThreats, sn.OpenIncidents, sn.ActiveMissions)
	if len(sn.TopThreats) > 0 {
		b.WriteString("- Threats: " + strings.Join(sn.TopThreats, "; ") + "\n")
	}
	if len(sn.OpenIncidentTit) > 0 {
		b.WriteString("- Open incidents: " + strings.Join(sn.OpenIncidentTit, "; ") + "\n")
	}
	if strings.TrimSpace(viewing) != "" {
		b.WriteString("\nThe analyst is currently viewing: " + viewing + "\n")
	}
	return b.String()
}

// simulatedReply produces a useful, data-grounded answer with no LLM, so the
// assistant works in the demo even when neither Ollama nor Claude is available.
func (s *Service) simulatedReply(ctx context.Context, message string) string {
	sn := s.gather(ctx)
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "threat") || strings.Contains(m, "hostile") || strings.Contains(m, "tahdid"):
		if len(sn.TopThreats) == 0 {
			return "No active threat tracks are currently in the common operating picture."
		}
		return fmt.Sprintf("There are %d threat tracks (%d critical). Current tracks: %s.",
			sn.Threats, sn.CriticalThreats, strings.Join(sn.TopThreats, "; "))
	case strings.Contains(m, "incident") || strings.Contains(m, "security") || strings.Contains(m, "xavfsiz"):
		if len(sn.OpenIncidentTit) == 0 {
			return "No open security incidents right now."
		}
		return fmt.Sprintf("There are %d open security incidents: %s.",
			sn.OpenIncidents, strings.Join(sn.OpenIncidentTit, "; "))
	case strings.Contains(m, "sensor") || strings.Contains(m, "camera") || strings.Contains(m, "kamera") || strings.Contains(m, "surveil"):
		return fmt.Sprintf("The surveillance network has %d sensors feeding detections into the platform.", sn.Sensors)
	case strings.Contains(m, "mission") || strings.Contains(m, "operation") || strings.Contains(m, "missiya"):
		return fmt.Sprintf("There are %d active missions on the operations board.", sn.ActiveMissions)
	case strings.Contains(m, "entit") || strings.Contains(m, "graph") || strings.Contains(m, "summary") || strings.Contains(m, "overview"):
		return fmt.Sprintf("Platform snapshot — %d entities in the graph, %d sensors, %d threat tracks (%d critical), %d open incidents, %d active missions.",
			sn.Entities, sn.Sensors, sn.Threats, sn.CriticalThreats, sn.OpenIncidents, sn.ActiveMissions)
	default:
		return fmt.Sprintf("I'm the Ko'z analyst assistant (offline mode — no local or cloud model connected). "+
			"I can summarize live data: %d entities, %d sensors, %d threat tracks (%d critical), %d open incidents, %d active missions. "+
			"Ask me about threats, incidents, sensors, or missions. To enable full natural-language answers, run a local Ollama model or set an Anthropic API key.",
			sn.Entities, sn.Sensors, sn.Threats, sn.CriticalThreats, sn.OpenIncidents, sn.ActiveMissions)
	}
}
