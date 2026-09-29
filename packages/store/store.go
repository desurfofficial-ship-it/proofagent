package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/policy"
	"github.com/desurfofficial-ship-it/proofagent/packages/receipts"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	APIKey    string `json:"api_key,omitempty"` // only on create response
	CreatedAt string `json:"created_at"`
}

// Memory is the v0 in-memory store (swap for Postgres via DATABASE_URL later).
type Memory struct {
	mu             sync.RWMutex
	orgs           map[string]*Organization
	apiKeyHash     map[string]string // hash -> org_id
	agents         map[string]*schemas.Agent
	keys           map[string]*schemas.AgentKey
	agentActiveKey map[string]string
	policies       map[string]*policy.PolicyDocument
	agentPolicy    map[string]string
	auths          map[string]*schemas.Authorization
	receipts       map[string]*receipts.Receipt
	lastHash       map[string]string
	sequence       map[string]int64
	demoPriv       map[string]ed25519.PrivateKey
	passports      map[string]map[string]any
}

func NewMemory() *Memory {
	s := &Memory{
		orgs:           make(map[string]*Organization),
		apiKeyHash:     make(map[string]string),
		agents:         make(map[string]*schemas.Agent),
		keys:           make(map[string]*schemas.AgentKey),
		agentActiveKey: make(map[string]string),
		policies:       make(map[string]*policy.PolicyDocument),
		agentPolicy:    make(map[string]string),
		auths:          make(map[string]*schemas.Authorization),
		receipts:       make(map[string]*receipts.Receipt),
		lastHash:       make(map[string]string),
		sequence:       make(map[string]int64),
		demoPriv:       make(map[string]ed25519.PrivateKey),
		passports:      make(map[string]map[string]any),
	}
	s.policies["pol_demo"] = &policy.PolicyDocument{
		PolicyID: "pol_demo", Version: 4,
		Rules: []policy.Rule{
			{Effect: "allow", Action: "calendar.read"},
			{Effect: "allow", Action: "email.send", Conditions: map[string]any{"recipient_domain": []any{"company.com"}}},
			{Effect: "deny", Action: "stripe.create_payment", Conditions: map[string]any{"amount_gt": 100}},
			{Effect: "require_approval", Action: "stripe.create_payment", Conditions: map[string]any{"amount_gte": 50}},
			{Effect: "allow", Action: "stripe.create_payment"},
		},
	}
	// Default org for unauthenticated demo
	orgID := "org_default"
	key := "pk_demo_default_key_change_me"
	s.orgs[orgID] = &Organization{ID: orgID, Name: "Default", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	s.apiKeyHash[hashKey(key)] = orgID
	return s
}

func hashKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

func (s *Memory) CreateOrg(name string) (*Organization, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := fmt.Sprintf("org_%d", time.Now().UnixNano())
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	apiKey := "pk_" + hex.EncodeToString(b)
	o := &Organization{ID: id, Name: name, APIKey: apiKey, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	s.orgs[id] = o
	s.apiKeyHash[hashKey(apiKey)] = id
	return o, apiKey, nil
}

func (s *Memory) OrgFromAPIKey(apiKey string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.apiKeyHash[hashKey(apiKey)]
	return id, ok
}

func (s *Memory) CreateAgent(a *schemas.Agent, policyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.AgentID] = a
	if policyID == "" {
		policyID = "pol_demo"
	}
	s.agentPolicy[a.AgentID] = policyID
}

func (s *Memory) GetAgent(id string) (*schemas.Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	return a, ok
}

func (s *Memory) SetAgentStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	a.Status = status
	return nil
}

func (s *Memory) RegisterKey(k *schemas.AgentKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[k.KeyID] = k
	s.agentActiveKey[k.AgentID] = k.KeyID
}

func (s *Memory) GetActiveKey(agentID string) (*schemas.AgentKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kid := s.agentActiveKey[agentID]
	k, ok := s.keys[kid]
	return k, ok
}

func (s *Memory) SetDemoPriv(agentID string, priv ed25519.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.demoPriv[agentID] = priv
}

func (s *Memory) GetDemoPriv(agentID string) (ed25519.PrivateKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.demoPriv[agentID]
	return p, ok
}

func (s *Memory) GetPolicy(id string) (*policy.PolicyDocument, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	return p, ok
}

func (s *Memory) PutPolicy(p *policy.PolicyDocument) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.PolicyID] = p
}

func (s *Memory) AgentPolicyID(agentID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agentPolicy[agentID]
}

func (s *Memory) PutAuth(a *schemas.Authorization) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auths[a.AuthorizationID] = a
}

func (s *Memory) GetAuth(id string) (*schemas.Authorization, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.auths[id]
	return a, ok
}

func (s *Memory) UpdateAuthStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.auths[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	a.Status = status
	return nil
}

func (s *Memory) NextSequence(agentID string) (int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.sequence[agentID] + 1
	prev := s.lastHash[agentID]
	if prev == "" {
		prev = crypto.GenesisHash
	}
	return seq, prev
}

func (s *Memory) PutReceipt(agentID string, rec *receipts.Receipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts[rec.ReceiptID] = rec
	s.lastHash[agentID] = rec.ReceiptHash
	s.sequence[agentID] = rec.Sequence
}

func (s *Memory) GetReceipt(id string) (*receipts.Receipt, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.receipts[id]
	return r, ok
}


// ConsumeAuth atomically transitions approved/pending → consumed.
// Returns false if already consumed, denied, expired, or missing.
func (s *Memory) ConsumeAuth(id string, now time.Time) (*schemas.Authorization, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.auths[id]
	if !ok {
		return nil, false
	}
	if a.Status == "consumed" || a.Status == "denied" || a.Status == "expired" {
		return a, false
	}
	if a.Status != "approved" && a.Status != "pending" {
		return a, false
	}
	// REQUIRE_APPROVAL must be approved; ALLOW is auto-approved
	if a.Decision == "REQUIRE_APPROVAL" && a.Status != "approved" {
		return a, false
	}
	exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err == nil && now.After(exp) {
		a.Status = "expired"
		return a, false
	}
	a.Status = "consumed"
	return a, true
}

func (s *Memory) IssuePassport(agentID, keyID string, expiresAt time.Time) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	if a.Status != schemas.AgentStatusActive {
		return nil, fmt.Errorf("agent not active")
	}
	k, ok := s.keys[keyID]
	if !ok || k.AgentID != agentID || k.Status != "active" {
		return nil, fmt.Errorf("invalid key")
	}
	pid := fmt.Sprintf("psp_%d", time.Now().UnixNano())
	body := map[string]any{
		"passport_version": "0.1",
		"passport_id":      pid,
		"agent_id":         agentID,
		"principal":        map[string]any{"type": "human", "id": a.PrincipalID},
		"issuer":           map[string]any{"id": "proofagent", "type": "platform"},
		"agent": map[string]any{
			"name": a.Name, "runtime": a.Runtime,
			"runtime_version": a.RuntimeVersion, "agent_version": a.AgentVersion,
		},
		"public_key": map[string]any{"algorithm": "Ed25519", "key_id": keyID, "key": k.PublicKey},
		"issued_at":  time.Now().UTC().Format(time.RFC3339),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"status":     "active",
	}
	// Optional: sign with demo priv if available
	if priv, ok := s.demoPriv[agentID]; ok {
		hash, err := crypto.HashObject(body)
		if err == nil {
			if sig, err := crypto.SignReceiptHash(priv, hash); err == nil {
				body["signature"] = sig
				body["body_hash"] = hash
			}
		}
	}
	s.passports[pid] = body
	return body, nil
}

func (s *Memory) GetPassport(id string) (map[string]any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.passports[id]
	return p, ok
}

// JSON helper for debug
func MustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (s *Memory) Backend() string { return "memory" }
