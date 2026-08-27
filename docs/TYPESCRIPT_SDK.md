# 🔷 Peitho TypeScript & Node.js SDK Reference

The `@peithosecure/sdk` library provides TypeScript and JavaScript developers with high-level client tools to interact with the Peitho Security Gateway and wrap MCP tools.

---

## 📦 Installation

```bash
npm install @peithosecure/sdk
```

---

## 🚀 1. Quickstart & Client Setup

```typescript
import { PeithoClient } from '@peithosecure/sdk';

const client = new PeithoClient({
  gatewayUrl: 'http://127.0.0.1:4040/mcp'
});

// Check gateway health
const status = await client.getDiagnosticStatus();
console.log('Gateway status:', status);
```

---

## 🛡️ 2. Shielding Functions with `shield()`

Wrap your TypeScript tool functions with capability enforcement:

```typescript
import { shield } from '@peithosecure/sdk';

// Define a tool function
const fetchReport = async (uri: string) => {
  return `Downloaded report from ${uri}`;
};

// Protect the tool with a capability token
const protectedFetchReport = shield(fetchReport, {
  tokenHex: '50454954484f...', // Serialized Peitho capability token hex
  toolName: 'fetch_report'
});

// Invocation:
const result = await protectedFetchReport('s3://enterprise/public/q3.pdf');
console.log(result);
```

---

## 🤖 3. Executing MCP Tool Calls

Send structured JSON-RPC 2.0 tool calls through the Peitho Security Gateway:

```typescript
import { PeithoClient } from '@peithosecure/sdk';

const client = new PeithoClient({ gatewayUrl: 'http://127.0.0.1:4040/mcp' });

const response = await client.callTool({
  toolName: 'query_database',
  arguments: {
    target: 'postgres://staging/temp_cache/summary',
    query: 'SELECT count(*) FROM temp_cache'
  },
  principal: 'agent.database_ops',
  tokenHex: '50454954484f...'
});

console.log('Execution result:', response);
```
