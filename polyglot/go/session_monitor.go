package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// WebSocket endpoint for session monitoring
	sessionMonitorEndpoint = "/session-monitor"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Session struct {
	ID       string
	User     string
	Started  time.Time
	LastSeen time.Time
	Active   bool
}

type SessionMonitor struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

func NewSessionMonitor() *SessionMonitor {
	return &SessionMonitor{
		sessions: make(map[string]*Session),
	}
}

func (sm *SessionMonitor) AddSession(id, user string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.sessions[id] = &Session{
		ID:       id,
		User:     user,
		Started:  time.Now(),
		LastSeen: time.Now(),
		Active:   true,
	}
}

func (sm *SessionMonitor) UpdateSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[id]
	if !exists {
		return
	}

	session.LastSeen = time.Now()
	session.Active = true
}

func (sm *SessionMonitor) RemoveSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, id)
}

func (sm *SessionMonitor) GetSessions() map[string]*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[string]*Session)
	for k, v := range sm.sessions {
		result[k] = v
	}
	return result
}

func (sm *SessionMonitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}

	for {
		// Simulate session updates
		time.Sleep(5 * time.Second)
		sm.UpdateSession("session-123")

		// Send session data to client
		sessionData := sm.GetSessions()
		if err := conn.WriteJSON(sessionData); err != nil {
			log.Println("write:", err)
			break
		}
	}
}

func main() {
	mux := http.NewServeMux()
	sm := NewSessionMonitor()

	// Add initial session for demo
	sm.AddSession("session-123", "demo-user")

	mux.HandleFunc(sessionMonitorEndpoint, sm.ServeHTTP)

	fmt.Println("Starting session monitor server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal("server failed:", err)
	}
}