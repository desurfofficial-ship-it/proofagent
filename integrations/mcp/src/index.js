/**
 * ProofAgent MCP middleware — authorize → execute tool → observed receipt.
 * Result status comes from the tool return/throw, not from the caller.
 */

export class ProofMCP {
  constructor({ baseUrl = "http://localhost:8080", agentId, autoApprove = false, tools = {} }) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.agentId = agentId;
    this.autoApprove = autoApprove;
    this.tools = tools;
  }

  async #req(method, path, body) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || res.statusText);
      err.status = res.status;
      err.body = data;
      throw err;
    }
    return data;
  }

  async call(tool, context = {}) {
    if (typeof this.tools[tool] !== "function") {
      const err = new Error(`tool_not_registered: ${tool}`);
      err.status = 400;
      throw err;
    }

    const auth = await this.#req("POST", "/v1/authorize", {
      agent_id: this.agentId,
      action: { type: "tool_call", tool },
      context,
    });

    if (auth.decision === "DENY") {
      const err = new Error(`DENIED: ${auth.reason || "policy"}`);
      err.decision = "DENY";
      err.authorization = auth;
      throw err;
    }

    let authorizationId = auth.authorization_id;

    if (auth.decision === "REQUIRE_APPROVAL") {
      if (!this.autoApprove) {
        return { status: "awaiting_approval", authorization: auth };
      }
      await this.#req("POST", "/v1/approvals", {
        authorization_id: authorizationId,
        decision: "approve",
      });
    }

    // Observed execution
    let resultStatus = "success";
    let result;
    try {
      result = await this.tools[tool](context);
    } catch (e) {
      resultStatus = "error";
      result = { error: String(e && e.message ? e.message : e) };
    }

    const inputHash = "sha256:mcp_input";
    const resultHash = "sha256:mcp_result";

    const receipt = await this.#req("POST", "/v1/receipts", {
      agent_id: this.agentId,
      authorization_id: authorizationId,
      action: { type: "tool_call", tool },
      input_hash: inputHash,
      result_status: resultStatus,
      result_hash: resultHash,
    });

    const verification = await this.#req("POST", "/v1/verify", {
      receipt_id: receipt.receipt_id,
    });

    return {
      status: "completed",
      decision: auth.decision,
      result_status: resultStatus,
      result,
      receipt,
      verification,
      observation: { boundary: "proofagent.mcp" },
    };
  }
}

export default ProofMCP;
