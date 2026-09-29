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
      throw new ProofAgentError(
        (data && data.error) || res.statusText,
        res.status,
        data
      );
    }
    return data;
  }

  createAgent(opts: {
    name?: string;
    principal_id?: string;
    organization_id?: string;
    policy_id?: string;
  } = {}) {
    return this.req("POST", "/v1/agents", opts);
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

  submitReceipt(opts: {
    agent_id: string;
    authorization_id: string;
    tool: string;
    input_hash?: string;
    result_status?: string;
    result_hash?: string;
  }) {
    return this.req("POST", "/v1/receipts", {
      agent_id: opts.agent_id,
      authorization_id: opts.authorization_id,
      action: { type: "tool_call", tool: opts.tool },
      input_hash: opts.input_hash ?? "sha256:none",
      result_status: opts.result_status ?? "success",
      result_hash: opts.result_hash ?? "sha256:none",
    });
  }

  verify(receiptId: string) {
    return this.req("POST", "/v1/verify", { receipt_id: receiptId });
  }

  health() {
    return this.req("GET", "/health");
  }
}

export class Agent {
  constructor(
    public client: Client,
    public agentId: string,
    public privateKey?: string
  ) {}

  static async create(opts: {
    name?: string;
    principal_id?: string;
    baseUrl?: string;
    withDemoKey?: boolean;
  } = {}): Promise<Agent> {
    const client = new Client(opts.baseUrl);
    const a = await client.createAgent({
      name: opts.name ?? "agent",
      principal_id: opts.principal_id,
    });
    let priv: string | undefined;
    if (opts.withDemoKey !== false) {
      const kp = await client.demoKeypair(a.agent_id);
      priv = kp.private_key;
    }
    return new Agent(client, a.agent_id, priv);
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

    const receipt = await this.client.submitReceipt({
      agent_id: this.agentId,
      authorization_id: authId,
      tool,
    });
    out.receipt = receipt;
    out.verification = await this.client.verify(receipt.receipt_id);
    out.status = "completed";
    return out;
  }
}
