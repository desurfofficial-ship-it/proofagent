"""
Execution boundary — ProofAgent observes real tool outcomes.

    authorize → invoke tool → capture result → hash I/O → sign receipt → submit

The agent cannot invent result_status without the tool actually returning it.
"""

from __future__ import annotations

import hashlib
import json
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .client import Agent, Client, ProofAgentError
from . import crypto_local


def _stable_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass
class ObservedExecution:
    tool: str
    decision: str
    authorization_id: str
    input_hash: str
    result_status: str
    result_hash: str
    result: Any = None
    error: Optional[str] = None
    receipt: Optional[dict] = None
    verification: Optional[dict] = None
    duration_ms: float = 0.0


@dataclass
class ToolBoundary:
    """
    Registers tools and runs them only after a successful authorization.

    Usage:
        agent = Agent.create(name="Finance", client_side_keys=True)
        boundary = ToolBoundary(agent)
        boundary.tool("stripe.create_payment")(create_payment_fn)
        out = boundary.run("stripe.create_payment", {"amount": 25})
    """

    agent: Agent
    tools: dict[str, Callable[..., Any]] = field(default_factory=dict)
    auto_approve: bool = False

    def tool(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[name] = fn
            return fn

        return decorator

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        self.tools[name] = fn

    def run(
        self,
        tool: str,
        context: Optional[dict] = None,
        *,
        approve: bool | None = None,
    ) -> ObservedExecution:
        context = context or {}
        if tool not in self.tools:
            raise ProofAgentError(f"tool_not_registered: {tool}", status=400)

        # 1) Authorize
        auth = self.agent.authorize(tool, context)
        decision = auth.get("decision")
        auth_id = auth["authorization_id"]

        if decision == "DENY":
            raise ProofAgentError(
                f"DENIED: {auth.get('reason', 'policy')}",
                status=403,
                body=auth,
            )

        if decision == "REQUIRE_APPROVAL":
            do_approve = self.auto_approve if approve is None else approve
            if not do_approve:
                return ObservedExecution(
                    tool=tool,
                    decision=decision,
                    authorization_id=auth_id,
                    input_hash=_stable_hash(context),
                    result_status="awaiting_approval",
                    result_hash="sha256:none",
                )
            self.agent.client.approve(auth_id, "approve")

        # 2) Execute under boundary — observed
        input_hash = _stable_hash(context)
        t0 = time.perf_counter()
        result_status = "success"
        result: Any = None
        err: Optional[str] = None
        try:
            result = self.tools[tool](**context) if _accepts_kwargs(self.tools[tool]) else self.tools[tool](context)
        except TypeError:
            # fallback: pass context as single arg
            try:
                result = self.tools[tool](context)
            except Exception as e:
                result_status = "error"
                err = f"{type(e).__name__}: {e}"
                result = {"error": err, "trace": traceback.format_exc()[-500:]}
        except Exception as e:
            result_status = "error"
            err = f"{type(e).__name__}: {e}"
            result = {"error": err, "trace": traceback.format_exc()[-500:]}

        duration_ms = (time.perf_counter() - t0) * 1000
        result_hash = _stable_hash({"status": result_status, "result": result})

        # 3) Submit observed evidence.
        # Prefer client-side sign only for local 32-byte seeds; demo (Go 64-byte)
        # keys use server sign so canonicalization matches packages/crypto.
        use_client_sign = False
        if self.agent.private_key and crypto_local._HAS_CRYPTO:
            import base64
            raw = base64.b64decode(self.agent.private_key)
            use_client_sign = len(raw) in (32, 64)

        if use_client_sign:
            try:
                self.agent._seq += 1
                body = {
                    "receipt_version": "0.1",
                    "receipt_id": f"rcpt_obs_{int(time.time() * 1e9)}",
                    "sequence": self.agent._seq,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "principal": {"id": ""},
                    "agent": {"id": self.agent.agent_id, "version": ""},
                    "authorization": {
                        "authorization_id": auth_id,
                        "decision": decision,
                    },
                    "action": {"type": "tool_call", "tool": tool},
                    "input": {"hash": input_hash},
                    "result": {"status": result_status, "hash": result_hash},
                    "previous_receipt_hash": self.agent._prev_hash,
                }
                signed = crypto_local.build_signed_receipt(body, self.agent.private_key)
                receipt = self.agent.client.submit_receipt(
                    {
                        "agent_id": self.agent.agent_id,
                        "authorization_id": auth_id,
                        "action": body["action"],
                        "input_hash": input_hash,
                        "result_status": result_status,
                        "result_hash": result_hash,
                        "receipt": signed,
                    }
                )
                self.agent._prev_hash = signed["receipt_hash"]
                verification = self.agent.client.verify(
                    receipt_id=receipt.get("receipt_id"),
                    public_key=self.agent.public_key,
                )
            except ProofAgentError:
                # Fall back to server sign (canonicalization mismatch safety)
                use_client_sign = False

        if not use_client_sign:
            receipt = self.agent.client.submit_receipt(
                {
                    "agent_id": self.agent.agent_id,
                    "authorization_id": auth_id,
                    "action": {"type": "tool_call", "tool": tool},
                    "input_hash": input_hash,
                    "result_status": result_status,
                    "result_hash": result_hash,
                }
            )
            verification = self.agent.client.verify(receipt_id=receipt.get("receipt_id"))

        return ObservedExecution(
            tool=tool,
            decision=decision,
            authorization_id=auth_id,
            input_hash=input_hash,
            result_status=result_status,
            result_hash=result_hash,
            result=result,
            error=err,
            receipt=receipt,
            verification=verification,
            duration_ms=duration_ms,
        )


def _accepts_kwargs(fn: Callable[..., Any]) -> bool:
    import inspect

    try:
        sig = inspect.signature(fn)
        return any(
            p.kind in (p.VAR_KEYWORD, p.KEYWORD_ONLY) or p.default is not p.empty
            for p in sig.parameters.values()
        ) or all(p.kind == p.POSITIONAL_OR_KEYWORD for p in sig.parameters.values())
    except (TypeError, ValueError):
        return False
