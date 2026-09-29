package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/policy"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

type Store struct {
	mu          sync.RWMutex
	agents      map[string]*schemas.Agent
	keys        map[string]*schemas.AgentKey
	policies    map[string]*policy.PolicyDocument // policy_id -> current
	agentPolicy map[string]string                 // agent_id -> policy_id
	auths       map[string]*schemas.Authorization
}

func NewStore() *Store {
	s := &Store{
		agents:      make(map[string]*schemas.Agent),
		keys:        make(map[string]*schemas.AgentKey),
		policies:    make(map[string]*policy.PolicyDocument),
		agentPolicy: make(map[string]string),
		auths:       make(map[string]*schemas.Authorization),
	}
	// Default demo policy for the canonical demo
	demo := &policy.PolicyDocument{
		PolicyID: "pol_demo",
		Version:  4,
		Rules: []policy.Rule{
			{Effect: "allow", Action: "calendar.read"},
			{Effect: "allow", Action: "email.send", Conditions: map[string]any{
				"recipient_domain": []any{"company.com"},
			}},
			{Effect: "deny", Action: "stripe.create_payment", Conditions: map[string]any{
				"amount_gt": 100,
			}},
			{Effect: "require_approval", Action: "stripe.create_payment", Conditions: map[string]any{
				"amount_gte": 50,
			}},
			{Effect: "allow", Action: "stripe.create_payment"},
		},
	}
	s.policies["pol_demo"] = demo
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
			PolicyID       string `json:"policy_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		if body.OrganizationID == "" {
			body.OrganizationID = "org_default"
		}
		if body.PolicyID == "" {
			body.PolicyID = "pol_demo"
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
		store.mu.Lock()
		store.agents[id] = a
		store.agentPolicy[id] = body.PolicyID
		store.mu.Unlock()
		writeJSON(w, 201, a)
	})

	mux.HandleFunc("GET /v1/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		store.mu.RLock()
		a, ok := store.agents[id]
		store.mu.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, a)
	})

	mux.HandleFunc("POST /v1/agents/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		store.mu.RLock()
		_, ok := store.agents[agentID]
		store.mu.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "agent not found"})
			return
		}
		var body struct {
			PublicKey string `json:"public_key"`
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
		store.mu.Lock()
		store.keys[keyID] = k
		store.mu.Unlock()
		writeJSON(w, 201, k)
	})

	mux.HandleFunc("POST /v1/policies", func(w http.ResponseWriter, r *http.Request) {
		var doc policy.PolicyDocument
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		if doc.PolicyID == "" {
			doc.PolicyID = fmt.Sprintf("pol_%d", time.Now().UnixNano())
		}
		if doc.Version == 0 {
			doc.Version = 1
		}
		store.mu.Lock()
		store.policies[doc.PolicyID] = &doc
		store.mu.Unlock()
		writeJSON(w, 201, doc)
	})

	mux.HandleFunc("GET /v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		store.mu.RLock()
		p, ok := store.policies[id]
		store.mu.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, p)
	})

	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID string         `json:"agent_id"`
			Action  map[string]any `json:"action"`
			Context map[string]any `json:"context"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		store.mu.RLock()
		agent, ok := store.agents[body.AgentID]
		polID := store.agentPolicy[body.AgentID]
		pol := store.policies[polID]
		store.mu.RUnlock()
		if !ok || agent.Status != schemas.AgentStatusActive {
			writeJSON(w, 403, map[string]string{"error": "agent_inactive_or_missing", "decision": policy.Deny})
			return
		}
		if pol == nil {
			writeJSON(w, 403, map[string]any{"decision": policy.Deny, "reason": "no_policy"})
			return
		}

		tool, _ := body.Action["tool"].(string)
		typ, _ := body.Action["type"].(string)
		target, _ := body.Action["target"].(string)
		req := policy.ActionRequest{Type: typ, Tool: tool, Target: target, Context: body.Context}
		res := policy.Evaluate(pol, req)

		authID := fmt.Sprintf("auth_%d", time.Now().UnixNano())
		now := time.Now().UTC()
		exp := now.Add(90 * time.Second)
		auth := &schemas.Authorization{
			AuthorizationID: authID,
			AgentID:         body.AgentID,
			Action:          body.Action,
			Context:         body.Context,
			Decision:        res.Decision,
			PolicyID:        pol.PolicyID,
			PolicyVersion:   pol.Version,
			Nonce:           nonce(),
			IssuedAt:        now.Format(time.RFC3339),
			ExpiresAt:       exp.Format(time.RFC3339),
			Status:          "pending",
		}
		if res.Decision == policy.Deny {
			auth.Status = "denied"
		}
		store.mu.Lock()
		store.auths[authID] = auth
		store.mu.Unlock()

		writeJSON(w, 200, map[string]any{
			"decision":         res.Decision,
			"reason":           res.Reason,
			"authorization_id": authID,
			"policy": map[string]any{
				"id":      pol.PolicyID,
				"version": pol.Version,
			},
			"expires_at": exp.Format(time.RFC3339),
			"nonce":      auth.Nonce,
		})
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	addr := ":8080"
	log.Printf("ProofAgent API listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
