package store

import (
	"crypto/ed25519"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/policy"
	"github.com/desurfofficial-ship-it/proofagent/packages/receipts"
	"github.com/desurfofficial-ship-it/proofagent/packages/schemas"
)

// Store is the persistence boundary. Memory, File, and (later) Postgres implement this.
type Store interface {
	CreateOrg(name string) (*Organization, string, error)
	OrgFromAPIKey(apiKey string) (string, bool)

	CreateAgent(a *schemas.Agent, policyID string)
	GetAgent(id string) (*schemas.Agent, bool)
	SetAgentStatus(id, status string) error

	RegisterKey(k *schemas.AgentKey)
	GetActiveKey(agentID string) (*schemas.AgentKey, bool)
	SetDemoPriv(agentID string, priv ed25519.PrivateKey)
	GetDemoPriv(agentID string) (ed25519.PrivateKey, bool)

	GetPolicy(id string) (*policy.PolicyDocument, bool)
	PutPolicy(p *policy.PolicyDocument)
	AgentPolicyID(agentID string) string

	PutAuth(a *schemas.Authorization)
	GetAuth(id string) (*schemas.Authorization, bool)
	UpdateAuthStatus(id, status string) error
	ConsumeAuth(id string, now time.Time) (*schemas.Authorization, bool)

	NextSequence(agentID string) (int64, string)
	PutReceipt(agentID string, rec *receipts.Receipt)
	GetReceipt(id string) (*receipts.Receipt, bool)

	IssuePassport(agentID, keyID string, expiresAt time.Time) (map[string]any, error)
	GetPassport(id string) (map[string]any, bool)

	Backend() string
}
