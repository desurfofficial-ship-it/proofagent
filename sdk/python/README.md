# proofagent-python

Python SDK for ProofAgent.

Target developer experience:

```python
from proofagent import Agent

agent = Agent(agent_id="agt_123", private_key=PRIVATE_KEY)

result = agent.execute(
    tool="stripe.create_payment",
    arguments={"amount": 50, "currency": "USD"}
)
```

The SDK handles authorize → (approval if needed) → execute → create + sign + submit receipt.
