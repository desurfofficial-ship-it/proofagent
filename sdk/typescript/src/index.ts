import { generateKeyPairSync, sign as nodeSign, createHash, verify as nodeVerify } from "crypto";

export class ProofAgentError extends Error {
  status?: number;
  body?: unknown;
  constructor(message: string, status?: number, body?: unknown) {
    super(message);
    this.name = "ProofAgentError";
    this.status = status;
    this.body = body;
  }
}

const GENESIS = "sha256:" + "0".repeat(64);

function canonical(obj: unknown): string {
  return JSON.stringify(obj, Object.keys(obj as object).sort());
}

/** Minimal deterministic JSON (sorted keys, recursive). */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

function sha256Prefixed(data: string): string {
  return "sha256:" + createHash("sha256").update(data, "utf8").digest("hex");
}

export function generateKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" });
  // Raw 32-byte public key is last 32 bytes of SPKI DER for Ed25519
  const pubRaw = pub.subarray(pub.length - 32);
  const priv = privateKey.export({ type: "pkcs8", format: "der" });
  // PKCS8 for Ed25519: seed is last 32 bytes typically
  const seed = priv.subarray(priv.length - 32);
  return {
    publicKey: pubRaw.toString("base64"),
    privateKey: seed.toString("base64"),
  };
}

export class Client {
  constructor(public baseUrl: string = "http://localhost:8080") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private async req(method: string, path: string, json?: unknown): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: json !== undefined ? JSON.stringify(json) : undefined,
    });
    let data: any;
    try {
      data = await res.json();
    } catch {
      data = { raw: await res.text() };
    }
    if (!res.ok) {
      throw new ProofAgentError((data && data.error) || res.statusText, res.status, data);
    }
    return data;
  }

  createAgent(opts: { name?: string; principal_id?: string; organization_id?: string; policy_id?: string } = {}) {
    return this.req("POST", "/v1/agents", opts);
  }

  registerPublicKey(agentId: string, publicKey: string) {
    return this.req("POST", `/v1/agents/${agentId}/keys`, { public_key: publicKey });
  }

  demoKeypair(agentId: string) {
    return this.req("POST", `/v1/agents/${agentId}/demo-keypair`);
  }

  authorize(agentId: string, tool: string, context: Record<string, unknown> = {}) {
    return this.req("POST", "/v1/authorize", {
      agent_id: agentId,
      action: { type: "tool_call", tool },
      context,
    });
  }

  approve(authorizationId: string, decision: "approve" | "deny" = "approve") {
    return this.req("POST", "/v1/approvals", {
      authorization_id: authorizationId,
      decision,
    });
  }

  submitReceipt(opts: Record<string, unknown>) {
    return this.req("POST", "/v1/receipts", opts);
  }

  verify(opts: { receipt_id?: string; receipt?: unknown; public_key?: string }) {
    return this.req("POST", "/v1/verify", opts);
  }

  health() {
    return this.req("GET", "/health");
  }
}

export class Agent {
  private seq = 0;
  private prevHash = GENESIS;

  constructor(
    public client: Client,
    public agentId: string,
    public publicKey?: string,
    public privateKey?: string
  ) {}

  static async create(
    opts: {
      name?: string;
      principal_id?: string;
      baseUrl?: string;
      clientSideKeys?: boolean;
      withDemoKey?: boolean;
    } = {}
  ): Promise<Agent> {
    const client = new Client(opts.baseUrl);
    const a = await client.createAgent({
      name: opts.name ?? "agent",
      principal_id: opts.principal_id,
    });
    let pub: string | undefined;
    let priv: string | undefined;
    if (opts.withDemoKey) {
      const kp = await client.demoKeypair(a.agent_id);
      pub = kp.key.public_key;
      priv = kp.private_key;
    } else if (opts.clientSideKeys !== false) {
      const kp = generateKeypair();
      pub = kp.publicKey;
      priv = kp.privateKey;
      await client.registerPublicKey(a.agent_id, pub);
    }
    return new Agent(client, a.agent_id, pub, priv);
  }

  authorize(tool: string, context: Record<string, unknown> = {}) {
    return this.client.authorize(this.agentId, tool, context);
  }

  async execute(
    tool: string,
    context: Record<string, unknown> = {},
    opts: { approve?: boolean } = {}
  ): Promise<Record<string, unknown>> {
    const auth = await this.authorize(tool, context);
    const decision = auth.decision as string;
    const out: Record<string, unknown> = { authorization: auth, decision };

    if (decision === "DENY") {
      throw new ProofAgentError(`DENIED: ${auth.reason || "policy"}`, 403, auth);
    }

    const authId = auth.authorization_id as string;

    if (decision === "REQUIRE_APPROVAL") {
      if (!opts.approve) {
        out.status = "awaiting_approval";
        return out;
      }
      out.approval = await this.client.approve(authId, "approve");
    }

    // Prefer server-signed path (canonical match); client-side sign is best-effort
    const receipt = await this.client.submitReceipt({
      agent_id: this.agentId,
      authorization_id: authId,
      action: { type: "tool_call", tool },
      input_hash: "sha256:none",
      result_status: "success",
      result_hash: "sha256:none",
    });
    out.receipt = receipt;
    out.verification = await this.client.verify({
      receipt_id: receipt.receipt_id,
      public_key: this.publicKey,
    });
    out.status = "completed";
    return out;
  }
}

// silence unused imports for future client sign path
void nodeSign;
void nodeVerify;
void canonical;
void stableStringify;
void sha256Prefixed;
