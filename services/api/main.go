package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/policy"
	"github.com/desurfofficial-ship-it/proofagent/packages/receipts"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

type Store struct {
	mu             sync.RWMutex
	agents         map[string]*schemas.Agent
	keys           map[string]*schemas.AgentKey // key_id
	agentActiveKey map[string]string            // agent_id -> key_id
	policies       map[string]*policy.PolicyDocument
	agentPolicy    map[string]string
	auths          map[string]*schemas.Authorization
	approvals      map[string]string // authorization_id -> "approved"|"denied"
	receipts       map[string]*receipts.Receipt
	lastHash       map[string]string // agent_id -> last receipt_hash
	sequence       map[string]int64  // agent_id -> last sequence
	// Demo: hold private keys only for test agents that generate keys via /v1/demo/keypair
	demoPriv       map[string]ed25519.PrivateKey // agent_id -> priv (demo only)
}

func NewStore() *Store {
	s := &Store{
		agents:         make(map[string]*schemas.Agent),
		keys:           make(map[string]*schemas.AgentKey),
		agentActiveKey: make(map[string]string),
		policies:       make(map[string]*policy.PolicyDocument),
		agentPolicy:    make(map[string]string),
		auths:          make(map[string]*schemas.Authorization),
		approvals:      make(map[string]string),
		receipts:       make(map[string]*receipts.Receipt),
		lastHash:       make(map[string]string),
		sequence:       make(map[string]int64),
		demoPriv:       make(map[string]ed25519.PrivateKey),
	}
	s.policies["pol_demo"] = &policy.PolicyDocument{
		PolicyID: "pol_demo",
		Version:  4,
		Rules: []policy.Rule{
			{Effect: "allow", Action: "calendar.read"},
			{Effect: "allow", Action: "email.send", Conditions: map[string]any{"recipient_domain": []any{"company.com"}}},
			{Effect: "deny", Action: "stripe.create_payment", Conditions: map[string]any{"amount_gt": 100}},
			{Effect: "require_approval", Action: "stripe.create_payment", Conditions: map[string]any{"amount_gte": 50}},
			{Effect: "allow", Action: "stripe.create_payment"},
		},
	}
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
			Name, Runtime, RuntimeVersion, AgentVersion, OrganizationID, PrincipalID, PolicyID string
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
			AgentID: id, OrganizationID: body.OrganizationID, PrincipalID: body.PrincipalID,
			Name: body.Name, Runtime: body.Runtime, RuntimeVersion: body.RuntimeVersion,
			AgentVersion: body.AgentVersion, Status: schemas.AgentStatusActive,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		store.mu.Lock()
		store.agents[id] = a
		store.agentPolicy[id] = body.PolicyID
		store.mu.Unlock()
		writeJSON(w, 201, a)
	})

	mux.HandleFunc("GET /v1/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		a, ok := store.agents[r.PathValue("id")]
		store.mu.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, a)
	})

	// Demo helper: generate keypair, register public key, return private key once (dev only)
	mux.HandleFunc("POST /v1/agents/{id}/demo-keypair", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		store.mu.Lock()
		defer store.mu.Unlock()
		if _, ok := store.agents[agentID]; !ok {
			writeJSON(w, 404, map[string]string{"error": "agent not found"})
			return
		}
		pub, priv, err := crypto.GenerateKeyPair()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "keygen"})
			return
		}
		keyID := fmt.Sprintf("key_%d", time.Now().UnixNano())
		k := &schemas.AgentKey{
			KeyID: keyID, AgentID: agentID, Algorithm: "Ed25519",
			PublicKey: crypto.PublicKeyToBase64(pub), Status: "active",
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		store.keys[keyID] = k
		store.agentActiveKey[agentID] = keyID
		store.demoPriv[agentID] = priv
		writeJSON(w, 201, map[string]any{
			"key":         k,
			"private_key": base64.StdEncoding.EncodeToString(priv),
			"note":        "demo only — private key returned once; production never stores priv server-side",
		})
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
			KeyID: keyID, AgentID: agentID, Algorithm: "Ed25519", PublicKey: body.PublicKey,
			Status: "active", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		store.mu.Lock()
		store.keys[keyID] = k
		store.agentActiveKey[agentID] = keyID
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
		store.mu.RLock()
		p, ok := store.policies[r.PathValue("id")]
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
			writeJSON(w, 403, map[string]any{"decision": policy.Deny, "error": "agent_inactive_or_missing"})
			return
		}
		if pol == nil {
			writeJSON(w, 403, map[string]any{"decision": policy.Deny, "reason": "no_policy"})
			return
		}
		tool, _ := body.Action["tool"].(string)
		typ, _ := body.Action["type"].(string)
		target, _ := body.Action["target"].(string)
		res := policy.Evaluate(pol, policy.ActionRequest{Type: typ, Tool: tool, Target: target, Context: body.Context})
		authID := fmt.Sprintf("auth_%d", time.Now().UnixNano())
		now := time.Now().UTC()
		exp := now.Add(90 * time.Second)
		status := "pending"
		if res.Decision == policy.Deny {
			status = "denied"
		} else if res.Decision == policy.Allow {
			status = "approved" // auto-approved for ALLOW
		}
		auth := &schemas.Authorization{
			AuthorizationID: authID, AgentID: body.AgentID, Action: body.Action, Context: body.Context,
			Decision: res.Decision, PolicyID: pol.PolicyID, PolicyVersion: pol.Version,
			Nonce: nonce(), IssuedAt: now.Format(time.RFC3339), ExpiresAt: exp.Format(time.RFC3339), Status: status,
		}
		store.mu.Lock()
		store.auths[authID] = auth
		store.mu.Unlock()
		writeJSON(w, 200, map[string]any{
			"decision": res.Decision, "reason": res.Reason, "authorization_id": authID,
			"policy": map[string]any{"id": pol.PolicyID, "version": pol.Version},
			"expires_at": exp.Format(time.RFC3339), "nonce": auth.Nonce,
		})
	})

	// PA-023: approve or deny a REQUIRE_APPROVAL authorization
	mux.HandleFunc("POST /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AuthorizationID string `json:"authorization_id"`
			Decision        string `json:"decision"` // approve | deny
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		auth, ok := store.auths[body.AuthorizationID]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "authorization not found"})
			return
		}
		if auth.Decision != policy.RequireApproval {
			writeJSON(w, 400, map[string]string{"error": "not_pending_approval"})
			return
		}
		if auth.Status == "consumed" || auth.Status == "denied" {
			writeJSON(w, 409, map[string]string{"error": "already_resolved"})
			return
		}
		exp, _ := time.Parse(time.RFC3339, auth.ExpiresAt)
		if time.Now().UTC().After(exp) {
			auth.Status = "expired"
			writeJSON(w, 410, map[string]string{"error": "expired"})
			return
		}
		d := body.Decision
		if d == "approve" {
			auth.Status = "approved"
			store.approvals[auth.AuthorizationID] = "approved"
		} else {
			auth.Status = "denied"
			store.approvals[auth.AuthorizationID] = "denied"
		}
		writeJSON(w, 200, map[string]any{"authorization_id": auth.AuthorizationID, "status": auth.Status})
	})

	// Submit a signed receipt (client-signed) OR demo server-side sign when demo key exists
	mux.HandleFunc("POST /v1/receipts", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID         string         `json:"agent_id"`
			AuthorizationID string         `json:"authorization_id"`
			Action          map[string]any `json:"action"`
			InputHash       string         `json:"input_hash"`
			ResultStatus    string         `json:"result_status"`
			ResultHash      string         `json:"result_hash"`
			// Optional client-provided signed receipt
			Receipt *receipts.Receipt `json:"receipt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}

		store.mu.Lock()
		defer store.mu.Unlock()

		agent, ok := store.agents[body.AgentID]
		if !ok || agent.Status != schemas.AgentStatusActive {
			writeJSON(w, 403, map[string]string{"error": "agent_inactive"})
			return
		}
		auth, ok := store.auths[body.AuthorizationID]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "authorization not found"})
			return
		}
		if auth.AgentID != body.AgentID {
			writeJSON(w, 403, map[string]string{"error": "agent_mismatch"})
			return
		}
		if auth.Status == "consumed" {
			writeJSON(w, 409, map[string]string{"error": "REPLAY_DETECTED"})
			return
		}
		if auth.Decision == policy.Deny || auth.Status == "denied" {
			writeJSON(w, 403, map[string]string{"error": "not_authorized"})
			return
		}
		if auth.Decision == policy.RequireApproval && auth.Status != "approved" {
			writeJSON(w, 403, map[string]string{"error": "approval_required"})
			return
		}
		exp, _ := time.Parse(time.RFC3339, auth.ExpiresAt)
		if time.Now().UTC().After(exp) {
			writeJSON(w, 410, map[string]string{"error": "authorization_expired"})
			return
		}

		prev := store.lastHash[body.AgentID]
		if prev == "" {
			prev = crypto.GenesisHash
		}
		seq := store.sequence[body.AgentID] + 1
		rcptID := fmt.Sprintf("rcpt_%d", time.Now().UnixNano())

		rb := receipts.Body{
			ReceiptVersion: "0.1",
			ReceiptID:      rcptID,
			Sequence:       seq,
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Principal:      map[string]any{"id": agent.PrincipalID},
			Agent:          map[string]any{"id": agent.AgentID, "version": agent.AgentVersion},
			Authorization: map[string]any{
				"authorization_id": auth.AuthorizationID,
				"decision":         auth.Decision,
			},
			Policy: map[string]any{"policy_id": auth.PolicyID, "version": auth.PolicyVersion},
			Action: body.Action,
			Input:  map[string]any{"hash": body.InputHash},
			Result: map[string]any{"status": body.ResultStatus, "hash": body.ResultHash},
			PreviousReceiptHash: prev,
		}
		if auth.Decision == policy.RequireApproval {
			rb.Approval = map[string]any{"status": "approved"}
		}

		var rec *receipts.Receipt
		if body.Receipt != nil {
			rec = body.Receipt
		} else {
			priv, hasPriv := store.demoPriv[body.AgentID]
			if !hasPriv {
				writeJSON(w, 400, map[string]string{"error": "provide receipt or use demo-keypair first"})
				return
			}
			var err error
			rec, err = receipts.Build(rb, priv)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}

		// Verify before accept
		keyID := store.agentActiveKey[body.AgentID]
		k := store.keys[keyID]
		if k == nil {
			writeJSON(w, 400, map[string]string{"error": "no_active_key"})
			return
		}
		pub, err := crypto.PublicKeyFromBase64(k.PublicKey)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad_public_key"})
			return
		}
		vr := receipts.Verify(rec, pub, prev)
		if !vr.Valid {
			writeJSON(w, 400, map[string]any{"error": "invalid_receipt", "checks": vr.Checks})
			return
		}

		auth.Status = "consumed"
		store.receipts[rec.ReceiptID] = rec
		store.lastHash[body.AgentID] = rec.ReceiptHash
		store.sequence[body.AgentID] = seq
		writeJSON(w, 201, rec)
	})

	mux.HandleFunc("GET /v1/receipts/{id}", func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		rec, ok := store.receipts[r.PathValue("id")]
		store.mu.RUnlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, rec)
	})

	mux.HandleFunc("POST /v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ReceiptID string            `json:"receipt_id"`
			Receipt   *receipts.Receipt `json:"receipt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		store.mu.RLock()
		rec := body.Receipt
		if rec == nil && body.ReceiptID != "" {
			rec = store.receipts[body.ReceiptID]
		}
		if rec == nil {
			store.mu.RUnlock()
			writeJSON(w, 404, map[string]string{"error": "receipt not found"})
			return
		}
		agentID, _ := rec.Agent["id"].(string)
		keyID := store.agentActiveKey[agentID]
		k := store.keys[keyID]
		prev := rec.PreviousReceiptHash
		store.mu.RUnlock()
		if k == nil {
			writeJSON(w, 400, map[string]string{"error": "no_key"})
			return
		}
		pub, err := crypto.PublicKeyFromBase64(k.PublicKey)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad_key"})
			return
		}
		vr := receipts.Verify(rec, pub, prev)
		writeJSON(w, 200, vr)
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	log.Printf("ProofAgent API listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
