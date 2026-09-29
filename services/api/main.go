package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

// In-memory store for v0 vertical slice. Replace with Postgres later.
type Store struct {
	mu     sync.RWMutex
	agents map[string]*schemas.Agent
	keys   map[string]*schemas.AgentKey // key_id -> key
}

func NewStore() *Store {
	return &Store{
		agents: make(map[string]*schemas.Agent),
		keys:   make(map[string]*schemas.AgentKey),
	}
}

func (s *Store) CreateAgent(a *schemas.Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.AgentID] = a
}

func (s *Store) GetAgent(id string) (*schemas.Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	return a, ok
}

func (s *Store) RegisterKey(k *schemas.AgentKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[k.KeyID] = k
}

func (s *Store) GetKey(id string) (*schemas.AgentKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	return k, ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	store := NewStore()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name           string `json:"name"`
			Runtime        string `json:"runtime"`
			RuntimeVersion string `json:"runtime_version"`
			AgentVersion   string `json:"agent_version"`
			OrganizationID string `json:"organization_id"`
			PrincipalID    string `json:"principal_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		if body.OrganizationID == "" {
			body.OrganizationID = "org_default"
		}
		id := fmt.Sprintf("agt_%d", time.Now().UnixNano())
		a := &schemas.Agent{
			AgentID:        id,
			OrganizationID: body.OrganizationID,
			PrincipalID:    body.PrincipalID,
			Name:           body.Name,
			Runtime:        body.Runtime,
			RuntimeVersion: body.RuntimeVersion,
			AgentVersion:   body.AgentVersion,
			Status:         schemas.AgentStatusActive,
			CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		}
		store.CreateAgent(a)
		writeJSON(w, 201, a)
	})

	mux.HandleFunc("GET /v1/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		a, ok := store.GetAgent(id)
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, a)
	})

	mux.HandleFunc("POST /v1/agents/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		if _, ok := store.GetAgent(agentID); !ok {
			writeJSON(w, 404, map[string]string{"error": "agent not found"})
			return
		}
		var body struct {
			PublicKey string `json:"public_key"` // base64 Ed25519
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		pub, err := crypto.PublicKeyFromBase64(body.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			writeJSON(w, 400, map[string]string{"error": "invalid public key"})
			return
		}
		keyID := fmt.Sprintf("key_%d", time.Now().UnixNano())
		k := &schemas.AgentKey{
			KeyID:     keyID,
			AgentID:   agentID,
			Algorithm: "Ed25519",
			PublicKey: body.PublicKey,
			Status:    "active",
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		store.RegisterKey(k)
		writeJSON(w, 201, k)
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	addr := ":8080"
	log.Printf("ProofAgent API listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
