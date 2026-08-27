/**
 * Types and interfaces for PeithoSecure TypeScript SDK.
 */

export interface PeithoClientOptions {
  /** Base URL for the Peitho gateway (default: "http://127.0.0.1:4040") */
  baseUrl?: string;
  /** Optional timeout in milliseconds */
  timeoutMs?: number;
}

export interface EvaluationResult {
  allowed: boolean;
  outcome: 'ALLOW' | 'DENY';
  reason?: string;
  invariant?: string;
  latencyMicros?: number;
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface ShieldOptions {
  toolName: string;
  readOnly?: boolean;
}
