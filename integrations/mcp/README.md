# ProofAgent MCP Middleware

```js
import { ProofMCP } from "./src/index.js";

const mcp = new ProofMCP({
  agentId: "agt_...",
  autoApprove: true, // dev only
  tools: {
    "stripe.create_payment": async (ctx) => ({ status: "success", amount: ctx.amount }),
  },
});

const out = await mcp.call("stripe.create_payment", { amount: 25 });
// out.verification.valid === true
```

Flow: **identify → authorize → approval → execute → receipt → verify**
