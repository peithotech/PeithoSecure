import { PeithoClientOptions, JsonRpcRequest, JsonRpcResponse, EvaluationResult } from './types.js';

/**
 * Client for interacting with the local PeithoSecure cryptographic kernel & MCP gateway.
 */
export class PeithoClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: PeithoClientOptions = {}) {
    this.baseUrl = options.baseUrl || 'http://127.0.0.1:4040';
    this.timeoutMs = options.timeoutMs || 5000;
  }

  /**
   * Check health and connectivity to the local Peitho node.
   */
  async getStatus(): Promise<{ status: string; version: string; instance: string }> {
    const res = await fetch(`${this.baseUrl}/api/v1/system`, {
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) {
      throw new Error(`Peitho node returned HTTP ${res.status}: ${res.statusText}`);
    }
    const data = await res.json() as Record<string, any>;
    return {
      status: 'HEALTHY',
      version: '0.1.0',
      instance: data.runtime?.platform || 'Single Local Node',
    };
  }

  /**
   * Send an MCP tool call request through the Peitho security gateway.
   *
   * @param request JSON-RPC 2.0 request payload
   * @param tokenHex Optional hex-encoded post-quantum capability token
   */
  async sendMcpRequest(request: JsonRpcRequest, tokenHex?: string): Promise<JsonRpcResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (tokenHex) {
      headers['X-Peitho-Capability'] = tokenHex;
    }

    const res = await fetch(`${this.baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    return (await res.json()) as JsonRpcResponse;
  }

  /**
   * Trigger a simulated authorization test on the local daemon.
   */
  async runSelfTest(scenario: 'valid_authorization' | 'unauthorized_tool' | 'resource_traversal'): Promise<void> {
    await fetch(`${this.baseUrl}/api/v1/self-test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
  }
}
