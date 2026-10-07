// Package handlers provides WebSocket streaming for real-time alerts.
package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now
	},
}

// WebSocketServer handles real-time alert streaming.
type WebSocketServer struct {
	clients    map[*WebSocketClient]bool
	broadcast  chan *database.Alert
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
	mu         sync.RWMutex
}

// WebSocketClient represents a connected WebSocket client.
type WebSocketClient struct {
	conn    *websocket.Conn
	send    chan []byte
	server  *WebSocketServer
	filters AlertStreamFilters
	mu      sync.RWMutex
}

// AlertStreamFilters defines client subscription filters.
type AlertStreamFilters struct {
	Severity []string `json:"severity,omitempty"`
	RuleID   string   `json:"rule_id,omitempty"`
	AgentID  string   `json:"agent_id,omitempty"`
}

// WebSocketMessage is a generic WebSocket message.
type WebSocketMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// SubscribeMessage is sent by clients to filter alerts.
type SubscribeMessage struct {
	Type    string             `json:"type"`
	Filters AlertStreamFilters `json:"filters"`
}

// AlertStreamMessage is an alert broadcast to clients.
type AlertStreamMessage struct {
	Type string         `json:"type"`
	Data *AlertResponse `json:"data"`
}

// NewWebSocketServer creates a new WebSocket server.
func NewWebSocketServer() *WebSocketServer {
	return &WebSocketServer{
		clients:    make(map[*WebSocketClient]bool),
		broadcast:  make(chan *database.Alert, 256),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
	}
}

// RegisterRoutes registers WebSocket routes.
func (s *WebSocketServer) RegisterRoutes(r *mux.Router) {
	// Exact path + GET method — must be registered BEFORE any wildcard routes
	// (e.g. /sigma/alerts/{alert_id}) so gorilla/mux doesn't shadow this endpoint.
	r.HandleFunc("/sigma/alerts/stream", s.HandleConnection).Methods("GET")
}

// Start begins the WebSocket server loop.
func (s *WebSocketServer) Start() {
	go s.run()
	go s.heartbeat()
	logger.Info("WebSocket server started")
}

// run processes client registration and broadcasts.
func (s *WebSocketServer) run() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client] = true
			s.mu.Unlock()
			logger.Infof("WebSocket client connected (total: %d)", len(s.clients))

		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
			s.mu.Unlock()
			logger.Infof("WebSocket client disconnected (total: %d)", len(s.clients))

		case alert := <-s.broadcast:
			s.mu.RLock()
			for client := range s.clients {
				if s.matchesFilters(alert, client.filters) {
					msg := AlertStreamMessage{
						Type: "alert",
						Data: toAlertResponse(alert),
					}
					data, _ := json.Marshal(msg)
					select {
					case client.send <- data:
					default:
						// Client buffer full, skip
					}
				}
			}
			s.mu.RUnlock()
		}
	}
}

// heartbeat sends periodic ping messages.
func (s *WebSocketServer) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.RLock()
		for client := range s.clients {
			ping := WebSocketMessage{Type: "ping"}
			data, _ := json.Marshal(ping)
			select {
			case client.send <- data:
			default:
			}
		}
		s.mu.RUnlock()
	}
}

// matchesFilters checks if alert matches client filters.
func (s *WebSocketServer) matchesFilters(alert *database.Alert, filters AlertStreamFilters) bool {
	// Empty filters = receive all
	if len(filters.Severity) == 0 && filters.RuleID == "" && filters.AgentID == "" {
		return true
	}

	// Check severity
	if len(filters.Severity) > 0 {
		matched := false
		for _, sev := range filters.Severity {
			if alert.Severity == sev {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check rule ID
	if filters.RuleID != "" && alert.RuleID != filters.RuleID {
		return false
	}

	// Check agent ID
	if filters.AgentID != "" && alert.AgentID != filters.AgentID {
		return false
	}

	return true
}

// BroadcastAlert sends an alert to all matching clients.
func (s *WebSocketServer) BroadcastAlert(alert *database.Alert) {
	select {
	case s.broadcast <- alert:
	default:
		logger.Warn("Broadcast channel full, dropping alert")
	}
}

// ClientCount returns the number of connected clients.
func (s *WebSocketServer) ClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// HandleConnection handles new WebSocket connections.
func (s *WebSocketServer) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorf("WebSocket upgrade error: %v", err)
		return
	}

	client := &WebSocketClient{
		conn:   conn,
		send:   make(chan []byte, 256),
		server: s,
	}

	s.register <- client

	go client.writePump()
	go client.readPump()
}

// readPump reads messages from the client.
func (c *WebSocketClient) readPump() {
	defer func() {
		c.server.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(8192)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Errorf("WebSocket read error: %v", err)
			}
			break
		}

		// Parse message
		var msg WebSocketMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "subscribe":
			var sub SubscribeMessage
			if err := json.Unmarshal(message, &sub); err == nil {
				c.mu.Lock()
				c.filters = sub.Filters
				c.mu.Unlock()
				logger.Infof("Client subscribed to filters: %+v", sub.Filters)
			}
		case "pong":
			// Heartbeat response, ignore
		}
	}
}

// writePump sends messages to the client.
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// One JSON document per WebSocket frame. Coalescing several
			// messages into one frame (newline-joined) made the dashboard's
			// single JSON.parse fail, dropping every alert in a burst.
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

			// Drain what is already queued without waiting, still one frame each.
			n := len(c.send)
			for i := 0; i < n; i++ {
				c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := c.conn.WriteMessage(websocket.TextMessage, <-c.send); err != nil {
					return
				}
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
