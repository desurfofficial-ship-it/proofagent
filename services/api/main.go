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
	"os"
	"strings"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/policy"
	"github.com/desurfofficial-ship-it/proofagent/packages/receipts"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
	"github.com/desurfofficial-ship-it/proofagent/packages/store"
)

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

func bearerOrg(r *http.Request, s store.Store) (string, bool) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return s.OrgFromAPIKey(strings.TrimPrefix(h, "Bearer "))
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		return s.OrgFromAPIKey(k)
	}
	// STRICT_AUTH=1 requires API key; otherwise demo mode uses org_default
	if os.Getenv("STRICT_AUTH") == "1" || os.Getenv("STRICT_AUTH") == "true" {
		return "", false
	}
	return "org_default", true
}

func main() {
	var s store.Store
	dataDir := os.Getenv("PROOFAGENT_DATA")
	if dataDir != "" {
		fs, err := store.OpenFile(dataDir)
		if err != nil {
			log.Fatalf("open data dir %s: %v", dataDir, err)
		}
		s = fs
		log.Printf("durable store: %s", s.Backend())
	} else {
		s = store.NewMemory()
		log.Printf("store: memory (set PROOFAGENT_DATA=/path for durability)")
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(dashboardHTML)
})

	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(dashboardHTML)
})

	mux.HandleFunc("GET /v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{
			"product": "ProofAgent",
			"version": "0.1.0",
			"api":     "v1",
		})
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "store": s.Backend()})
	})

	// --- Organizations ---
	mux.HandleFunc("POST /v1/organizations", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			writeJSON(w, 400, map[string]string{"error": "name required"})
			return
		}
		o, key, err := s.CreateOrg(body.Name)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 201, map[string]any{
			"id": o.ID, "name": o.Name, "api_key": key, "created_at": o.CreatedAt,
			"note": "store api_key securely; it is shown only once",
		})
	})

	// --- Agents ---
	mux.HandleFunc("POST /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		orgID, ok := bearerOrg(r, s)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		var body struct {
			Name, Runtime, RuntimeVersion, AgentVersion, PrincipalID, PolicyID string
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		id := fmt.Sprintf("agt_%d", time.Now().UnixNano())
		a := &schemas.Agent{
			AgentID: id, OrganizationID: orgID, PrincipalID: body.PrincipalID,
			Name: body.Name, Runtime: body.Runtime, RuntimeVersion: body.RuntimeVersion,
			AgentVersion: body.AgentVersion, Status: schemas.AgentStatusActive,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		s.CreateAgent(a, body.PolicyID)
		writeJSON(w, 201, a)
	})

	mux.HandleFunc("GET /v1/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.GetAgent(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, a)
	})

	mux.HandleFunc("POST /v1/agents/{id}/suspend", func(w http.ResponseWriter, r *http.Request) {
		if err := s.SetAgentStatus(r.PathValue("id"), schemas.AgentStatusSuspended); err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "suspended"})
	})

	mux.HandleFunc("POST /v1/agents/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := s.SetAgentStatus(r.PathValue("id"), schemas.AgentStatusRevoked); err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "revoked"})
	})

	mux.HandleFunc("POST /v1/agents/{id}/activate", func(w http.ResponseWriter, r *http.Request) {
		if err := s.SetAgentStatus(r.PathValue("id"), schemas.AgentStatusActive); err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "active"})
	})

	mux.HandleFunc("POST /v1/agents/{id}/demo-keypair", func(w http.ResponseWriter, r *http.Request) {
		// DEMO ONLY — production agents must generate keys client-side and POST public key only.
		if os.Getenv("PROOFAGENT_DEMO") == "0" {
			writeJSON(w, 403, map[string]string{"error": "demo_keypair_disabled", "hint": "generate keypair client-side; POST /v1/agents/{id}/keys with public_key only"})
			return
		}
		agentID := r.PathValue("id")
		if _, ok := s.GetAgent(agentID); !ok {
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
		s.RegisterKey(k)
		s.SetDemoPriv(agentID, priv)
		writeJSON(w, 201, map[string]any{
			"key": k, "private_key": base64.StdEncoding.EncodeToString(priv),
			"note": "demo only",
		})
	})

	mux.HandleFunc("POST /v1/agents/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		if _, ok := s.GetAgent(agentID); !ok {
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
		s.RegisterKey(k)
		writeJSON(w, 201, k)
	})

	// --- Passports ---
	mux.HandleFunc("POST /v1/passports", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID   string `json:"agent_id"`
			KeyID     string `json:"key_id"`
			ExpiresIn int    `json:"expires_in_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		if body.ExpiresIn <= 0 {
			body.ExpiresIn = 90
		}
		// default key: active key for agent
		if body.KeyID == "" {
			k, ok := s.GetActiveKey(body.AgentID)
			if !ok {
				writeJSON(w, 400, map[string]string{"error": "no_active_key"})
				return
			}
			body.KeyID = k.KeyID
		}
		p, err := s.IssuePassport(body.AgentID, body.KeyID, time.Now().AddDate(0, 0, body.ExpiresIn))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 201, p)
	})

	mux.HandleFunc("GET /v1/passports/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.GetPassport(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, p)
	})

	// --- Policies ---
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
		s.PutPolicy(&doc)
		writeJSON(w, 201, doc)
	})

	mux.HandleFunc("GET /v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.GetPolicy(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, p)
	})

	// --- Authorize ---
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
		agent, ok := s.GetAgent(body.AgentID)
		if !ok || agent.Status != schemas.AgentStatusActive {
			writeJSON(w, 403, map[string]any{"decision": policy.Deny, "error": "agent_inactive_or_missing"})
			return
		}
		polID := s.AgentPolicyID(body.AgentID)
		pol, ok := s.GetPolicy(polID)
		if !ok {
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
			status = "approved"
		}
		auth := &schemas.Authorization{
			AuthorizationID: authID, AgentID: body.AgentID, Action: body.Action, Context: body.Context,
			Decision: res.Decision, PolicyID: pol.PolicyID, PolicyVersion: pol.Version,
			Nonce: nonce(), IssuedAt: now.Format(time.RFC3339), ExpiresAt: exp.Format(time.RFC3339), Status: status,
		}
		s.PutAuth(auth)
		writeJSON(w, 200, map[string]any{
			"decision": res.Decision, "reason": res.Reason, "authorization_id": authID,
			"policy": map[string]any{"id": pol.PolicyID, "version": pol.Version},
			"expires_at": exp.Format(time.RFC3339), "nonce": auth.Nonce,
		})
	})

	mux.HandleFunc("POST /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AuthorizationID string `json:"authorization_id"`
			Decision        string `json:"decision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		auth, ok := s.GetAuth(body.AuthorizationID)
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
			_ = s.UpdateAuthStatus(auth.AuthorizationID, "expired")
			writeJSON(w, 410, map[string]string{"error": "expired"})
			return
		}
		st := "denied"
		if body.Decision == "approve" {
			st = "approved"
		}
		_ = s.UpdateAuthStatus(auth.AuthorizationID, st)
		writeJSON(w, 200, map[string]any{"authorization_id": auth.AuthorizationID, "status": st})
	})

	mux.HandleFunc("POST /v1/receipts", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID         string         `json:"agent_id"`
			AuthorizationID string         `json:"authorization_id"`
			InputHash       string         `json:"input_hash"`
			ResultStatus    string         `json:"result_status"`
			ResultHash      string         `json:"result_hash"`
			Action          map[string]any `json:"action"`
			Receipt         *receipts.Receipt `json:"receipt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		agent, ok := s.GetAgent(body.AgentID)
		if !ok || agent.Status != schemas.AgentStatusActive {
			writeJSON(w, 403, map[string]string{"error": "agent_inactive"})
			return
		}
		authProbe, ok := s.GetAuth(body.AuthorizationID)
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "authorization not found"})
			return
		}
		if authProbe.AgentID != body.AgentID {
			writeJSON(w, 403, map[string]string{"error": "agent_mismatch"})
			return
		}
		if authProbe.Status == "consumed" {
			writeJSON(w, 409, map[string]string{"error": "REPLAY_DETECTED"})
			return
		}
		if authProbe.Decision == policy.Deny || authProbe.Status == "denied" {
			writeJSON(w, 403, map[string]string{"error": "not_authorized"})
			return
		}
		if authProbe.Decision == policy.RequireApproval && authProbe.Status != "approved" {
			writeJSON(w, 403, map[string]string{"error": "approval_required"})
			return
		}
		// Atomic single-use consumption
		auth, ok := s.ConsumeAuth(body.AuthorizationID, time.Now().UTC())
		if !ok {
			if auth != nil && auth.Status == "consumed" {
				writeJSON(w, 409, map[string]string{"error": "REPLAY_DETECTED"})
				return
			}
			if auth != nil && auth.Status == "expired" {
				writeJSON(w, 410, map[string]string{"error": "authorization_expired"})
				return
			}
			writeJSON(w, 409, map[string]string{"error": "REPLAY_DETECTED"})
			return
		}

		seq, prev := s.NextSequence(body.AgentID)
		rcptID := fmt.Sprintf("rcpt_%d", time.Now().UnixNano())
		rb := receipts.Body{
			ReceiptVersion: "0.1", ReceiptID: rcptID, Sequence: seq,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Principal: map[string]any{"id": agent.PrincipalID},
			Agent:     map[string]any{"id": agent.AgentID, "version": agent.AgentVersion},
			Authorization: map[string]any{
				"authorization_id": auth.AuthorizationID, "decision": auth.Decision,
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
			priv, has := s.GetDemoPriv(body.AgentID)
			if !has {
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

		k, ok := s.GetActiveKey(body.AgentID)
		if !ok {
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
		s.PutReceipt(body.AgentID, rec)
		writeJSON(w, 201, rec)
	})

	mux.HandleFunc("GET /v1/receipts/{id}", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := s.GetReceipt(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, rec)
	})

mux.HandleFunc("GET /v1/receipts/{id}/bundle", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := s.GetReceipt(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		agentID, _ := rec.Agent["id"].(string)
		k, ok := s.GetActiveKey(agentID)
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "no_key"})
			return
		}
		bundle := map[string]any{
			"bundle_version": "0.1",
			"receipt":        rec,
			"public_key":     k.PublicKey,
			"algorithm":      "Ed25519",
			"note":           "Company B can verify offline with proofagent-verify -bundle this.json — no API required",
		}
		writeJSON(w, 200, bundle)
	})

	mux.HandleFunc("POST /v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ReceiptID string            `json:"receipt_id"`
			Receipt   *receipts.Receipt `json:"receipt"`
			PublicKey string            `json:"public_key"` // base64 Ed25519 — enables independent verify
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		rec := body.Receipt
		if rec == nil && body.ReceiptID != "" {
			rec, _ = s.GetReceipt(body.ReceiptID)
		}
		if rec == nil {
			writeJSON(w, 404, map[string]string{"error": "receipt not found"})
			return
		}

		var pub ed25519.PublicKey
		var err error
		if body.PublicKey != "" {
			pub, err = crypto.PublicKeyFromBase64(body.PublicKey)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "bad_public_key"})
				return
			}
		} else {
			agentID, _ := rec.Agent["id"].(string)
			k, ok := s.GetActiveKey(agentID)
			if !ok {
				writeJSON(w, 400, map[string]string{"error": "no_key_provide_public_key"})
				return
			}
			pub, err = crypto.PublicKeyFromBase64(k.PublicKey)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "bad_key"})
				return
			}
		}
		vr := receipts.Verify(rec, pub, rec.PreviousReceiptHash)
		writeJSON(w, 200, map[string]any{
			"valid":  vr.Valid,
			"checks": vr.Checks,
			"error":  vr.Error,
			"mode":   map[string]bool{"independent_key": body.PublicKey != ""},
		})
	})

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("ProofAgent API listening on %s (store=%s)", addr, s.Backend())
	log.Fatal(http.ListenAndServe(addr, mux))
}
