package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestAlertStreamDeliveryAndSaturationRecovery(t *testing.T) {
	for _, globalOverflow := range []bool{false, true} {
		t.Run(map[bool]string{false: "slow-client", true: "full-broadcast-queue"}[globalOverflow], func(t *testing.T) {
			accepted := make(chan *websocket.Conn, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err == nil {
					accepted <- conn
				}
			}))
			defer srv.Close()
			peer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
			require.NoError(t, err)
			defer peer.Close()
			conn := <-accepted
			defer conn.Close()
			server := NewWebSocketServer()
			client := &WebSocketClient{conn: conn, send: make(chan []byte, 1)}
			server.clients[client] = true
			a := &database.Alert{ID: "canonical", Severity: "high"}
			server.broadcastToClients(a)
			var msg struct {
				Type string `json:"type"`
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(<-client.send, &msg))
			require.Equal(t, "alert", msg.Type)
			require.Equal(t, "canonical", msg.Data.ID)
			client.filters = AlertStreamFilters{Severity: []string{"critical"}}
			server.broadcastToClients(a)
			require.Empty(t, client.send, "subscriptions must still filter updates")
			client.filters = AlertStreamFilters{}
			if globalOverflow {
				for i := 0; i < cap(server.broadcast); i++ {
					server.broadcast <- a
				}
				server.BroadcastAlert(a)
			} else {
				client.send <- []byte("already queued")
				server.broadcastToClients(a)
			}
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
			_, _, err = peer.ReadMessage()
			require.Error(t, err, "overflow must close the connection so the dashboard can reconcile")
			if netErr, ok := err.(interface{ Timeout() bool }); ok {
				require.False(t, netErr.Timeout(), "socket must close, not silently skip")
			}
		})
	}
}
