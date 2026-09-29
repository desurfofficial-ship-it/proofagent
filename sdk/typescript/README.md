# @proofagent/sdk

```bash
cd sdk/typescript && npm install && npm run build
```

```ts
import { Agent } from "@proofagent/sdk";

const agent = await Agent.create({ name: "FinanceBot" });
const result = await agent.execute(
  "stripe.create_payment",
  { amount: 75 },
  { approve: true }
);
console.log(result.verification); // { valid: true, ... }
```
