import { ShieldOptions } from './types.js';

/**
 * Higher-order function / wrapper to protect an AI Agent tool function with Peitho capability token enforcement.
 *
 * Example:
 * ```typescript
 * const protectedSearch = shield(
 *   { toolName: 'search_web', readOnly: true },
 *   async (query: string, token?: string) => {
 *     return `Search results for: ${query}`;
 *   }
 * );
 * ```
 */
export function shield<TArgs extends any[], TReturn>(
  options: ShieldOptions,
  fn: (...args: TArgs) => Promise<TReturn> | TReturn
): (...args: TArgs) => Promise<TReturn> {
  const { toolName } = options;

  return async (...args: TArgs): Promise<TReturn> => {
    // Look for token in the last argument if passed as an object with token property or string
    const lastArg = args[args.length - 1];
    let token: string | undefined;

    if (typeof lastArg === 'string') {
      token = lastArg;
    } else if (lastArg && typeof lastArg === 'object' && 'token' in lastArg) {
      token = (lastArg as { token?: string }).token;
    }

    if (!token) {
      throw new Error(`PeithoSecure: Missing capability token for tool '${toolName}'`);
    }

    return await fn(...args);
  };
}
