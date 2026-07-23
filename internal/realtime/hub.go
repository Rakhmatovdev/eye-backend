package realtime

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// threatTemplates seed the simulated live threat feed broadcast over /ws.
// Each entry mirrors the shape the Security Center frontend expects for a
// `type: "threat"` frame.
var threatTemplates = []map[string]interface{}{
	{"indicator": "91.219.237.19", "type": "ip", "severity": "critical", "source": "Internal IDS", "description": "Credential stuffing burst detected against auth-service", "tags": []string{"brute-force", "auth"}},
	{"indicator": "malicious-c2.ru", "type": "domain", "severity": "high", "source": "AlienVault OTX", "description": "Domain associated with active C2 infrastructure", "tags": []string{"c2", "malware"}},
	{"indicator": "45.155.205.87", "type": "ip", "severity": "critical", "source": "Suricata IDS", "description": "Ransomware staging host — mass file write pattern", "tags": []string{"ransomware"}},
	{"indicator": "185.220.101.4", "type": "ip", "severity": "high", "source": "AbuseIPDB", "description": "Tor exit node with elevated abuse confidence score", "tags": []string{"tor", "brute-force"}},
	{"indicator": "103.152.36.9", "type": "ip", "severity": "medium", "source": "Zeek NSM", "description": "Automated SQLi scanning tool signature detected", "tags": []string{"scanner", "web"}},
	{"indicator": "198.51.100.72", "type": "ip", "severity": "low", "source": "Internal IDS", "description": "Geo-velocity anomaly on active session token", "tags": []string{"impossible-travel"}},
	{"indicator": "203.0.113.44", "type": "ip", "severity": "medium", "source": "Cloudflare WAF", "description": "Part of a distributed volumetric traffic spike against api-gateway", "tags": []string{"ddos"}},
	{"indicator": "172.16.0.44", "type": "ip", "severity": "medium", "source": "Internal DLP", "description": "API key exceeded data export volume threshold", "tags": []string{"exfiltration"}},
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	Hub  *Hub
	Conn *websocket.Conn
	Send chan []byte
}

type Hub struct {
	Clients    map[*Client]bool
	Broadcast  chan []byte
	Register   chan *Client
	Unregister chan *Client
	mu         sync.Mutex
	log        *zap.Logger
}

func NewHub(log *zap.Logger) *Hub {
	return &Hub{
		Clients:    make(map[*Client]bool),
		Broadcast:  make(chan []byte),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		log:        log,
	}
}

func (h *Hub) Run() {
	go h.startSimulation()

	for {
		select {
		case client := <-h.Register:
			h.mu.Lock()
			h.Clients[client] = true
			h.mu.Unlock()
			h.log.Info("WS Client connected")

		case client := <-h.Unregister:
			h.mu.Lock()
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)
			}
			h.mu.Unlock()
			h.log.Info("WS Client disconnected")

		case message := <-h.Broadcast:
			h.mu.Lock()
			for client := range h.Clients {
				select {
				case client.Send <- message:
				default:
					close(client.Send)
					delete(h.Clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) startSimulation() {
	monitorTicker := time.NewTicker(2 * time.Second)
	threatTicker := time.NewTicker(4 * time.Second)
	defer monitorTicker.Stop()
	defer threatTicker.Stop()

	for {
		select {
		case <-monitorTicker.C:
			msg := map[string]interface{}{
				"type": "monitoring",
				"data": map[string]interface{}{
					"timestamp":           time.Now().Format(time.RFC3339),
					"cpu_usage":           40.0 + (time.Now().Sub(time.Now().Add(-1*time.Minute)).Seconds()),
					"memory_usage":        55.4,
					"active_connections":  len(h.Clients),
					"api_requests":        25 + int(time.Now().Unix()%20),
				},
			}
			h.broadcastIfConnected(msg)

		case <-threatTicker.C:
			tpl := threatTemplates[rand.Intn(len(threatTemplates))]
			msg := map[string]interface{}{
				"type": "threat",
				"data": map[string]interface{}{
					"indicator":   tpl["indicator"],
					"type":        tpl["type"],
					"severity":    tpl["severity"],
					"source":      tpl["source"],
					"description": tpl["description"],
					"tags":        tpl["tags"],
				},
			}
			h.broadcastIfConnected(msg)
		}
	}
}

// BroadcastMessage marshals msg to JSON and pushes it to every connected
// client (a no-op when nobody is connected). Exported so other packages —
// e.g. internal/alerts's rule evaluator — can push frames onto the same hub
// used by the built-in simulated feeds, following the same
// `{"type": ..., "data": ...}` frame shape.
func (h *Hub) BroadcastMessage(msg map[string]interface{}) {
	h.broadcastIfConnected(msg)
}

func (h *Hub) broadcastIfConnected(msg map[string]interface{}) {
	bytes, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.Lock()
	clientCount := len(h.Clients)
	h.mu.Unlock()
	if clientCount > 0 {
		h.Broadcast <- bytes
	}
}

func (c *Client) ReadPump() {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
	}()

	for {
		_, _, err := c.Conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Client) WritePump() {
	defer func() {
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		}
	}
}

func (h *Hub) ServeWS(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.log.Error("WS Upgrade error", zap.Error(err))
		return
	}

	client := &Client{Hub: h, Conn: conn, Send: make(chan []byte, 256)}
	h.Register <- client

	go client.WritePump()
	go client.ReadPump()
}
