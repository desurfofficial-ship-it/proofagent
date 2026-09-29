-- ProofAgent v0 schema
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  principal_id TEXT,
  name TEXT,
  runtime TEXT,
  runtime_version TEXT,
  agent_version TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  policy_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_keys (
  key_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  algorithm TEXT NOT NULL DEFAULT 'Ed25519',
  public_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS passports (
  passport_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  key_id TEXT NOT NULL,
  body JSONB NOT NULL,
  signature TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
  policy_id TEXT PRIMARY KEY,
  version INT NOT NULL,
  body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (policy_id, version)
);

CREATE TABLE IF NOT EXISTS authorizations (
  authorization_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  action JSONB NOT NULL,
  context JSONB,
  decision TEXT NOT NULL,
  policy_id TEXT,
  policy_version INT,
  nonce TEXT NOT NULL,
  status TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
  receipt_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  sequence BIGINT NOT NULL,
  body JSONB NOT NULL,
  receipt_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  previous_receipt_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (agent_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(organization_id);
CREATE INDEX IF NOT EXISTS idx_receipts_agent ON receipts(agent_id);
CREATE INDEX IF NOT EXISTS idx_auths_agent ON authorizations(agent_id);
