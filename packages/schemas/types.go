package schemas

// Agent status values.
const (
	AgentStatusActive    = "active"
	AgentStatusSuspended = "suspended"
	AgentStatusRevoked   = "revoked"
)

// Decision values from policy engine.
const (
	DecisionAllow            = "ALLOW"
	DecisionDeny             = "DENY"
	DecisionRequireApproval  = "REQUIRE_APPROVAL"
)

// Agent is the software actor.
type Agent struct {
	AgentID         string   `json:"agent_id"`
	OrganizationID  string   `json:"organization_id"`
	PrincipalID     string   `json:"principal_id,omitempty"`
	Name            string   `json:"name,omitempty"`
	Runtime         string   `json:"runtime,omitempty"`
	RuntimeVersion  string   `json:"runtime_version,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	Status          string   `json:"status"`
	CreatedAt       string   `json:"created_at"`
}

// AgentKey registers an Ed25519 public key for an agent.
type AgentKey struct {
	KeyID     string `json:"key_id"`
	AgentID   string `json:"agent_id"`
	Algorithm string `json:"algorithm"` // "Ed25519"
	PublicKey string `json:"public_key"` // base64
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

// Authorization is a short-lived grant for one action.
type Authorization struct {
	AuthorizationID string         `json:"authorization_id"`
	AgentID         string         `json:"agent_id"`
	Action          map[string]any `json:"action"`
	Context         map[string]any `json:"context,omitempty"`
	Decision        string         `json:"decision"`
	PolicyID        string         `json:"policy_id,omitempty"`
	PolicyVersion   int            `json:"policy_version,omitempty"`
	Nonce           string         `json:"nonce"`
	IssuedAt        string         `json:"issued_at"`
	ExpiresAt       string         `json:"expires_at"`
	Status          string         `json:"status"`
}

// ActionReceipt is the primary product artifact.
// When hashing/signing, exclude Signature and ReceiptHash from the body.
type ActionReceipt struct {
	ReceiptVersion      string         `json:"receipt_version"`
	ReceiptID           string         `json:"receipt_id"`
	Sequence            int64          `json:"sequence"`
	Timestamp           string         `json:"timestamp"`
	Principal           map[string]any `json:"principal"`
	Agent               map[string]any `json:"agent"`
	Authority           map[string]any `json:"authority,omitempty"`
	Authorization       map[string]any `json:"authorization"`
	Policy              map[string]any `json:"policy,omitempty"`
	Action              map[string]any `json:"action"`
	Input               map[string]any `json:"input,omitempty"`
	Result              map[string]any `json:"result,omitempty"`
	Approval            map[string]any `json:"approval,omitempty"`
	Security            map[string]any `json:"security,omitempty"`
	PreviousReceiptHash string         `json:"previous_receipt_hash"`
	ReceiptHash         string         `json:"receipt_hash,omitempty"`
	Signature           string         `json:"signature,omitempty"`
}
