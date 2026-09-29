/**
 * Lightweight MCP-style middleware wrapper.
 * Wraps tool handlers: authorize → (optional approval hook) → execute → submit receipt.
 *
 * Usage:
 *   import { ProofMCP } from "@proofagent/mcp-middleware";
 *   const server = new ProofMCP({ baseUrl, agentId, tools: { "stripe.create_payment": fn } });
 *   await server.call("stripe.create_payment", { amount: 25 });
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

    // Execute underlying tool if registered
    let result = { status: "success" };
    if (typeof this.tools[tool] === "function") {
      result = (await this.tools[tool](context)) || result;
    }

    const receipt = await this.#req("POST", "/v1/receipts", {
      agent_id: this.agentId,
      authorization_id: authorizationId,
      action: { type: "tool_call", tool },
      input_hash: "sha256:none",
      result_status: result.status || "success",
      result_hash: "sha256:none",
    });

    const verification = await this.#req("POST", "/v1/verify", {
      receipt_id: receipt.receipt_id,
    });

    return {
      status: "completed",
      decision: auth.decision,
      result,
      receipt,
      verification,
    };
  }
}

export default ProofMCP;
