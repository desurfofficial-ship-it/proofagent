from __future__ import annotations

from typing import Any, Optional

import httpx


class ProofAgentError(Exception):
    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class Client:
    """Low-level HTTP client for ProofAgent API."""

    def __init__(self, base_url: str = "http://localhost:8080", timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _req(self, method: str, path: str, json: Any = None) -> Any:
        r = self._http.request(method, path, json=json)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        if r.status_code >= 400:
            raise ProofAgentError(
                data.get("error", r.text) if isinstance(data, dict) else str(data),
                status=r.status_code,
                body=data,
            )
        return data

    def create_agent(
        self,
        name: str = "",
        principal_id: str = "",
        organization_id: str = "",
        policy_id: str = "",
        **kwargs: Any,
    ) -> dict:
        body = {"name": name, "principal_id": principal_id, **kwargs}
        if organization_id:
            body["organization_id"] = organization_id
        if policy_id:
            body["policy_id"] = policy_id
        return self._req("POST", "/v1/agents", body)

    def get_agent(self, agent_id: str) -> dict:
        return self._req("GET", f"/v1/agents/{agent_id}")

    def demo_keypair(self, agent_id: str) -> dict:
        """Dev helper: server generates keypair and registers public key."""
        return self._req("POST", f"/v1/agents/{agent_id}/demo-keypair")

    def authorize(
        self,
        agent_id: str,
        tool: str,
        context: Optional[dict] = None,
        action_type: str = "tool_call",
    ) -> dict:
        return self._req(
            "POST",
            "/v1/authorize",
            {
                "agent_id": agent_id,
                "action": {"type": action_type, "tool": tool},
                "context": context or {},
            },
        )

    def approve(self, authorization_id: str, decision: str = "approve") -> dict:
        return self._req(
            "POST",
            "/v1/approvals",
            {"authorization_id": authorization_id, "decision": decision},
        )

    def submit_receipt(
        self,
        agent_id: str,
        authorization_id: str,
        tool: str,
        input_hash: str = "sha256:none",
        result_status: str = "success",
        result_hash: str = "sha256:none",
        action_type: str = "tool_call",
    ) -> dict:
        return self._req(
            "POST",
            "/v1/receipts",
            {
                "agent_id": agent_id,
                "authorization_id": authorization_id,
                "action": {"type": action_type, "tool": tool},
                "input_hash": input_hash,
                "result_status": result_status,
                "result_hash": result_hash,
            },
        )

    def verify(self, receipt_id: str) -> dict:
        return self._req("POST", "/v1/verify", {"receipt_id": receipt_id})

    def health(self) -> dict:
        return self._req("GET", "/health")


class Agent:
    """
    High-level agent helper.

    Typical flow:
        agent = Agent.create(name="FinanceBot")
        result = agent.execute("stripe.create_payment", {"amount": 75}, approve=True)
    """

    def __init__(self, client: Client, agent_id: str, private_key: str | None = None):
        self.client = client
        self.agent_id = agent_id
        self.private_key = private_key

    @classmethod
    def create(
        cls,
        name: str = "agent",
        principal_id: str = "",
        base_url: str = "http://localhost:8080",
        with_demo_key: bool = True,
    ) -> "Agent":
        client = Client(base_url=base_url)
        a = client.create_agent(name=name, principal_id=principal_id)
        priv = None
        if with_demo_key:
            kp = client.demo_keypair(a["agent_id"])
            priv = kp.get("private_key")
        return cls(client, a["agent_id"], private_key=priv)

    def authorize(self, tool: str, context: Optional[dict] = None) -> dict:
        return self.client.authorize(self.agent_id, tool, context)

    def execute(
        self,
        tool: str,
        context: Optional[dict] = None,
        *,
        approve: bool = False,
        input_hash: str = "sha256:none",
        result_status: str = "success",
        result_hash: str = "sha256:none",
    ) -> dict:
        """
        authorize → optional approval → submit receipt → verify.

        Returns dict with decision, authorization, receipt, verification.
        Raises ProofAgentError on DENY or failed steps.
        """
        auth = self.authorize(tool, context)
        decision = auth.get("decision")
        out: dict[str, Any] = {"authorization": auth, "decision": decision}

        if decision == "DENY":
            raise ProofAgentError(
                f"DENIED: {auth.get('reason', 'policy')}",
                status=403,
                body=auth,
            )

        auth_id = auth["authorization_id"]

        if decision == "REQUIRE_APPROVAL":
            if not approve:
                out["status"] = "awaiting_approval"
                return out
            out["approval"] = self.client.approve(auth_id, "approve")

        receipt = self.client.submit_receipt(
            self.agent_id,
            auth_id,
            tool,
            input_hash=input_hash,
            result_status=result_status,
            result_hash=result_hash,
        )
        out["receipt"] = receipt
        verification = self.client.verify(receipt["receipt_id"])
        out["verification"] = verification
        out["status"] = "completed"
        return out
