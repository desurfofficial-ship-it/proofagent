from __future__ import annotations

from typing import Any, Optional
import time

import httpx

from . import crypto_local


class ProofAgentError(Exception):
    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class Client:
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

    def create_agent(self, name: str = "", principal_id: str = "", **kwargs: Any) -> dict:
        body = {"name": name, "principal_id": principal_id, **kwargs}
        return self._req("POST", "/v1/agents", body)

    def register_public_key(self, agent_id: str, public_key_b64: str) -> dict:
        return self._req("POST", f"/v1/agents/{agent_id}/keys", {"public_key": public_key_b64})

    def demo_keypair(self, agent_id: str) -> dict:
        """DEV ONLY — server holds private key. Prefer generate_keypair + register_public_key."""
        return self._req("POST", f"/v1/agents/{agent_id}/demo-keypair")

    def authorize(self, agent_id: str, tool: str, context: Optional[dict] = None) -> dict:
        return self._req(
            "POST",
            "/v1/authorize",
            {
                "agent_id": agent_id,
                "action": {"type": "tool_call", "tool": tool},
                "context": context or {},
            },
        )

    def approve(self, authorization_id: str, decision: str = "approve") -> dict:
        return self._req(
            "POST",
            "/v1/approvals",
            {"authorization_id": authorization_id, "decision": decision},
        )

    def submit_receipt(self, payload: dict) -> dict:
        return self._req("POST", "/v1/receipts", payload)

    def verify(self, receipt_id: str | None = None, receipt: dict | None = None, public_key: str | None = None) -> dict:
        body: dict[str, Any] = {}
        if receipt_id:
            body["receipt_id"] = receipt_id
        if receipt:
            body["receipt"] = receipt
        if public_key:
            body["public_key"] = public_key
        return self._req("POST", "/v1/verify", body)

    def health(self) -> dict:
        return self._req("GET", "/health")


class Agent:
    """
    Production trust model:
      local keygen → register public key only → authorize → sign receipt locally → submit → verify
    """

    def __init__(
        self,
        client: Client,
        agent_id: str,
        public_key: str | None = None,
        private_key: str | None = None,
    ):
        self.client = client
        self.agent_id = agent_id
        self.public_key = public_key
        self.private_key = private_key
        self._seq = 0
        self._prev_hash = crypto_local.GENESIS

    @classmethod
    def create(
        cls,
        name: str = "agent",
        principal_id: str = "",
        base_url: str = "http://localhost:8080",
        *,
        client_side_keys: bool = True,
        with_demo_key: bool = False,
    ) -> "Agent":
        client = Client(base_url=base_url)
        a = client.create_agent(name=name, principal_id=principal_id)
        agent_id = a["agent_id"]
        pub = priv = None
        if client_side_keys and not with_demo_key:
            pub, priv = crypto_local.generate_keypair()
            client.register_public_key(agent_id, pub)
        elif with_demo_key:
            kp = client.demo_keypair(agent_id)
            pub = kp["key"]["public_key"]
            priv = kp.get("private_key")
        return cls(client, agent_id, public_key=pub, private_key=priv)

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
        auth = self.authorize(tool, context)
        decision = auth.get("decision")
        out: dict[str, Any] = {"authorization": auth, "decision": decision}

        if decision == "DENY":
            raise ProofAgentError(f"DENIED: {auth.get('reason', 'policy')}", status=403, body=auth)

        auth_id = auth["authorization_id"]

        if decision == "REQUIRE_APPROVAL":
            if not approve:
                out["status"] = "awaiting_approval"
                return out
            out["approval"] = self.client.approve(auth_id, "approve")

        # Client-side signed receipt when we own the private key
        if self.private_key and self.public_key:
            self._seq += 1
            body = {
                "receipt_version": "0.1",
                "receipt_id": f"rcpt_local_{int(time.time()*1e9)}",
                "sequence": self._seq,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "principal": {"id": ""},
                "agent": {"id": self.agent_id, "version": ""},
                "authorization": {"authorization_id": auth_id, "decision": decision},
                "action": {"type": "tool_call", "tool": tool},
                "input": {"hash": input_hash},
                "result": {"status": result_status, "hash": result_hash},
                "previous_receipt_hash": self._prev_hash,
            }
            signed = crypto_local.build_signed_receipt(body, self.private_key)
            receipt = self.client.submit_receipt(
                {
                    "agent_id": self.agent_id,
                    "authorization_id": auth_id,
                    "action": body["action"],
                    "input_hash": input_hash,
                    "result_status": result_status,
                    "result_hash": result_hash,
                    "receipt": signed,
                }
            )
            self._prev_hash = signed["receipt_hash"]
        else:
            # Demo path: server signs
            receipt = self.client.submit_receipt(
                {
                    "agent_id": self.agent_id,
                    "authorization_id": auth_id,
                    "action": {"type": "tool_call", "tool": tool},
                    "input_hash": input_hash,
                    "result_status": result_status,
                    "result_hash": result_hash,
                }
            )

        out["receipt"] = receipt
        # Independent verify with public key when available
        verification = self.client.verify(
            receipt_id=receipt.get("receipt_id"),
            public_key=self.public_key,
        )
        out["verification"] = verification
        out["status"] = "completed"
        return out
