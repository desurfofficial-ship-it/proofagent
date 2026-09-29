package store

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/policy"
	"github.com/desurfofficial-ship-it/proofagent/packages/receipts"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

// File is a durable store using JSON files under root.
// Survives process restart. Not multi-process safe (single API instance).
type File struct {
	root string
	mu   sync.Mutex
	mem  *Memory // authoritative in-process; flushed to disk after mutations
}

type fileSnapshot struct {
	Orgs           map[string]*Organization            `json:"orgs"`
	APIKeyHash     map[string]string                   `json:"api_key_hash"`
	Agents         map[string]*schemas.Agent           `json:"agents"`
	Keys           map[string]*schemas.AgentKey        `json:"keys"`
	AgentActiveKey map[string]string                   `json:"agent_active_key"`
	Policies       map[string]*policy.PolicyDocument   `json:"policies"`
	AgentPolicy    map[string]string                   `json:"agent_policy"`
	Auths          map[string]*schemas.Authorization   `json:"auths"`
	Receipts       map[string]*receipts.Receipt        `json:"receipts"`
	LastHash       map[string]string                   `json:"last_hash"`
	Sequence       map[string]int64                    `json:"sequence"`
	Passports      map[string]map[string]any           `json:"passports"`
	DemoPriv       map[string]string                   `json:"demo_priv,omitempty"` // base64 private keys — demo only
}

// OpenFile loads or creates a durable store at dir.
func OpenFile(dir string) (*File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f := &File{root: dir, mem: NewMemory()}
	path := filepath.Join(dir, "state.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := f.flush(); err != nil {
				return nil, err
			}
			return f, nil
		}
		return nil, err
	}
	var snap fileSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("corrupt state.json: %w", err)
	}
	f.applySnapshot(&snap)
	return f, nil
}

func (f *File) applySnapshot(snap *fileSnapshot) {
	m := f.mem
	m.mu.Lock()
	defer m.mu.Unlock()
	if snap.Orgs != nil {
		m.orgs = snap.Orgs
	}
	if snap.APIKeyHash != nil {
		m.apiKeyHash = snap.APIKeyHash
	}
	if snap.Agents != nil {
		m.agents = snap.Agents
	}
	if snap.Keys != nil {
		m.keys = snap.Keys
	}
	if snap.AgentActiveKey != nil {
		m.agentActiveKey = snap.AgentActiveKey
	}
	if snap.Policies != nil {
		// keep pol_demo if missing
		for k, v := range snap.Policies {
			m.policies[k] = v
		}
	}
	if snap.AgentPolicy != nil {
		m.agentPolicy = snap.AgentPolicy
	}
	if snap.Auths != nil {
		m.auths = snap.Auths
	}
	if snap.Receipts != nil {
		m.receipts = snap.Receipts
	}
	if snap.LastHash != nil {
		m.lastHash = snap.LastHash
	}
	if snap.Sequence != nil {
		m.sequence = snap.Sequence
	}
	if snap.Passports != nil {
		m.passports = snap.Passports
	}
	if snap.DemoPriv != nil {
		for id, b64 := range snap.DemoPriv {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err == nil && len(raw) == ed25519.PrivateKeySize {
				m.demoPriv[id] = ed25519.PrivateKey(raw)
			}
		}
	}
}

func (f *File) snapshot() *fileSnapshot {
	m := f.mem
	m.mu.RLock()
	defer m.mu.RUnlock()
	demo := map[string]string{}
	for id, priv := range m.demoPriv {
		demo[id] = base64.StdEncoding.EncodeToString(priv)
	}
	// shallow copy maps for marshal
	return &fileSnapshot{
		Orgs: m.orgs, APIKeyHash: m.apiKeyHash, Agents: m.agents, Keys: m.keys,
		AgentActiveKey: m.agentActiveKey, Policies: m.policies, AgentPolicy: m.agentPolicy,
		Auths: m.auths, Receipts: m.receipts, LastHash: m.lastHash, Sequence: m.sequence,
		Passports: m.passports, DemoPriv: demo,
	}
}

func (f *File) flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	snap := f.snapshot()
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(f.root, "state.json.tmp")
	final := filepath.Join(f.root, "state.json")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func (f *File) Backend() string { return "file:" + f.root }

func (f *File) CreateOrg(name string) (*Organization, string, error) {
	o, k, err := f.mem.CreateOrg(name)
	if err != nil {
		return nil, "", err
	}
	_ = f.flush()
	return o, k, nil
}
func (f *File) OrgFromAPIKey(apiKey string) (string, bool) { return f.mem.OrgFromAPIKey(apiKey) }

func (f *File) CreateAgent(a *schemas.Agent, policyID string) {
	f.mem.CreateAgent(a, policyID)
	_ = f.flush()
}
func (f *File) GetAgent(id string) (*schemas.Agent, bool) { return f.mem.GetAgent(id) }
func (f *File) SetAgentStatus(id, status string) error {
	err := f.mem.SetAgentStatus(id, status)
	if err == nil {
		_ = f.flush()
	}
	return err
}

func (f *File) RegisterKey(k *schemas.AgentKey) {
	f.mem.RegisterKey(k)
	_ = f.flush()
}
func (f *File) GetActiveKey(agentID string) (*schemas.AgentKey, bool) {
	return f.mem.GetActiveKey(agentID)
}
func (f *File) SetDemoPriv(agentID string, priv ed25519.PrivateKey) {
	f.mem.SetDemoPriv(agentID, priv)
	_ = f.flush()
}
func (f *File) GetDemoPriv(agentID string) (ed25519.PrivateKey, bool) {
	return f.mem.GetDemoPriv(agentID)
}

func (f *File) GetPolicy(id string) (*policy.PolicyDocument, bool) { return f.mem.GetPolicy(id) }
func (f *File) PutPolicy(p *policy.PolicyDocument) {
	f.mem.PutPolicy(p)
	_ = f.flush()
}
func (f *File) AgentPolicyID(agentID string) string { return f.mem.AgentPolicyID(agentID) }

func (f *File) PutAuth(a *schemas.Authorization) {
	f.mem.PutAuth(a)
	_ = f.flush()
}
func (f *File) GetAuth(id string) (*schemas.Authorization, bool) { return f.mem.GetAuth(id) }
func (f *File) UpdateAuthStatus(id, status string) error {
	err := f.mem.UpdateAuthStatus(id, status)
	if err == nil {
		_ = f.flush()
	}
	return err
}
func (f *File) ConsumeAuth(id string, now time.Time) (*schemas.Authorization, bool) {
	a, ok := f.mem.ConsumeAuth(id, now)
	if ok {
		_ = f.flush()
	}
	return a, ok
}

func (f *File) NextSequence(agentID string) (int64, string) { return f.mem.NextSequence(agentID) }
func (f *File) PutReceipt(agentID string, rec *receipts.Receipt) {
	f.mem.PutReceipt(agentID, rec)
	_ = f.flush()
}
func (f *File) GetReceipt(id string) (*receipts.Receipt, bool) { return f.mem.GetReceipt(id) }

func (f *File) IssuePassport(agentID, keyID string, expiresAt time.Time) (map[string]any, error) {
	p, err := f.mem.IssuePassport(agentID, keyID, expiresAt)
	if err == nil {
		_ = f.flush()
	}
	return p, err
}
func (f *File) GetPassport(id string) (map[string]any, bool) { return f.mem.GetPassport(id) }

// Ensure Memory implements Store
var _ Store = (*Memory)(nil)
var _ Store = (*File)(nil)

// silence unused crypto import if any
var _ = crypto.GenesisHash
