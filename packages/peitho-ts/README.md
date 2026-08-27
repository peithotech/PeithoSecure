# @peithosecure/sdk

> Post-Quantum Capability Delegation & Zero-Trust Security Framework for AI Agents.

## Installation

```bash
npm install @peithosecure/sdk
```

## Quick Start

```typescript
import { PeithoClient, shield } from '@peithosecure/sdk';

// 1. Connect to local Peitho Security Gateway
const client = new PeithoClient({ baseUrl: 'http://127.0.0.1:4040' });

// 2. Wrap Agent Tools with @shield
const queryKnowledge = shield(
  { toolName: 'query_knowledge', readOnly: true },
  async (query: string, token?: string) => {
    return `Results for: ${query}`;
  }
);

// 3. Send intercepted tool call through MCP Gateway
const response = await client.sendMcpRequest(
  {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'query_knowledge',
      arguments: { query: 'post-quantum cryptography' },
    },
  },
  '0x4165676973546f6b656e...' // X-Peitho-Capability token hex
);
```

## License

Apache-2.0
