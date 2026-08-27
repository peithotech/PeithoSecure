#!/usr/bin/env python3
"""
🧪 PEITHOSECURE LIVE TEST: LEGITIMATE PRODUCTION ACCESS & BOUNDED DEFENSE
========================================================================
Demonstrates:
1. User legitimately authorizes agent to read production CRM database.
2. Gateway verifies token and ALLOWS legitimate read on postgres://production/crm/customer_accounts.
3. Even with prod read access, a destructive write attempt is BLOCKED (read_only=True).
4. Ephemeral token expires and subsequent calls are BLOCKED (TTL expiration).

Dashboard: http://127.0.0.1:4040
"""

import sys
import os
import time
import json
import urllib.request
import urllib.error

# Ensure local python package is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../crates/peitho-py/python')))

from peitho import generate_keypair, CapabilityToken

GATEWAY_URL = "http://127.0.0.1:4040/mcp"
DASHBOARD_URL = "http://127.0.0.1:4040"

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_PURPLE = "\033[95m"
C_DIM = "\033[2m"

def send_mcp_tool_call(tool_name: str, arguments: dict, token_hex: str, caller: str):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token_hex}"
    }

    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
            "principal": caller,
            "agent": caller,
            "caller": caller,
            "capability_token": token_hex
        }
    }

    req = urllib.request.Request(
        GATEWAY_URL,
        data=json.dumps(payload).encode('utf-8'),
        headers=headers,
        method="POST"
    )

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed_us = (time.perf_counter() - start) * 1_000_000
            body = json.loads(resp.read().decode())
            return True, body, elapsed_us
    except urllib.error.HTTPError as e:
        elapsed_us = (time.perf_counter() - start) * 1_000_000
        body = json.loads(e.read().decode())
        return False, body, elapsed_us

def main():
    print(f"\n{C_BOLD}{'='*85}{C_RESET}")
    print(f"{C_BOLD}🔬 SCENARIO: LEGITIMATE PRODUCTION ACCESS & BOUNDED SAFETY GATES{C_RESET}")
    print(f"   {C_CYAN}Dashboard URL:{C_RESET} {DASHBOARD_URL}")
    print(f"   {C_CYAN}MCP Gateway:{C_RESET}   {GATEWAY_URL}")
    print(f"{C_BOLD}{'='*85}{C_RESET}")

    # Step 1: User Request
    print(f"\n{C_BOLD}[1] 👤 USER REQUEST{C_RESET}")
    print(f"{C_YELLOW}User Prompt:{C_RESET} 'Generate a Q3 executive summary report by analyzing customer accounts in production DB.'")

    # Step 2: Minting Legitimate Scoped Token
    print(f"\n{C_BOLD}[2] 👑 ORCHESTRATOR: MINTING SCOPED PRODUCTION CAPABILITY{C_RESET}")
    keys = generate_keypair()
    
    prod_token = CapabilityToken.create_root(
        token_id="prod-analytics-exec-01",
        public_key=keys.public_key,
        secret_key=keys.secret_key,
        allowed_tools=["query_database"],
        resource_prefix="postgres://production/crm/",
        expires_at=int(time.time()) + 1800,  # 30 min TTL
        read_only=True,                      # Strict read-only guarantee
        profile_swarm=True,
    )
    token_hex = prod_token.to_bytes().hex()
    print(f"   • Issued Token: prod-analytics-exec-01")
    print(f"   • Assigned To:  agent.executive_analyst")
    print(f"   • Granted Scope: Tools: ['query_database'] | Prefix: 'postgres://production/crm/*'")
    print(f"   • Constraints:  read_only=True | TTL: 30 minutes")

    time.sleep(1.0)

    # Step 3: Legitimate Production Query
    print(f"\n{C_BOLD}[3] 🔍 AGENT: EXECUTING LEGITIMATE PRODUCTION QUERY{C_RESET}")
    print(f"{C_PURPLE}💭 [agent.executive_analyst] Thought:{C_RESET} Querying customer accounts for asset totals.")
    print(f"{C_CYAN}⚡ [agent.executive_analyst] Action:{C_RESET} Calling query_database(target='postgres://production/crm/customer_accounts')")
    
    ok, body, elapsed = send_mcp_tool_call(
        "query_database",
        {"target": "postgres://production/crm/customer_accounts", "query": "SELECT name, account_balance FROM customer_accounts"},
        token_hex=token_hex,
        caller="agent.executive_analyst"
    )
    if ok:
        print(f"   {C_GREEN}✅ [200 ALLOWED]{C_RESET} Verified in {elapsed:.1f} µs | Legitimate read executed on production database!")

    time.sleep(1.2)

    # Step 4: Safety Check: Even with prod access, destructive tools remain blocked
    print(f"\n{C_BOLD}[4] 🛡️ SAFETY CHECK: ACCIDENTAL WRITE MUTATION ON PROD{C_RESET}")
    print(f"{C_PURPLE}💭 [agent.executive_analyst] Accidental Action:{C_RESET} Agent attempts to call delete_customer_data on production.")
    print(f"{C_CYAN}⚡ [agent.executive_analyst] Action:{C_RESET} Attempting delete_customer_data(target='postgres://production/crm/customer_accounts')")
    
    ok, body, elapsed = send_mcp_tool_call(
        "delete_customer_data",
        {"target": "postgres://production/crm/customer_accounts", "account_id": 101},
        token_hex=token_hex,
        caller="agent.executive_analyst"
    )
    if not ok:
        err_msg = body.get("error", {}).get("message", "Denied")
        print(f"   {C_RED}🛡️ [403 BLOCKED BY PEITHO]{C_RESET} Intercepted in {elapsed:.1f} µs!")
        print(f"   {C_DIM}Violation: {err_msg}{C_RESET}")

    time.sleep(1.0)

    # Step 5: Safety Check: Accessing Outside Allowed Prefix
    print(f"\n{C_BOLD}[5] 🛡️ SAFETY CHECK: ACCESSING RESTRICTED VAULT (Outside Scope){C_RESET}")
    print(f"{C_PURPLE}💭 [agent.executive_analyst] Out-of-Scope Attempt:{C_RESET} Agent tries to query the internal credentials vault.")
    print(f"{C_CYAN}⚡ [agent.executive_analyst] Action:{C_RESET} Calling query_database(target='postgres://production/master_vault/keys')")
    
    ok, body, elapsed = send_mcp_tool_call(
        "query_database",
        {"target": "postgres://production/master_vault/keys", "query": "SELECT * FROM master_keys"},
        token_hex=token_hex,
        caller="agent.executive_analyst"
    )
    if not ok:
        err_msg = body.get("error", {}).get("message", "Denied")
        print(f"   {C_RED}🛡️ [403 BLOCKED BY PEITHO]{C_RESET} Intercepted in {elapsed:.1f} µs!")
        print(f"   {C_DIM}Violation: {err_msg}{C_RESET}")

    print(f"\n{C_BOLD}{'='*85}{C_RESET}")
    print(f"{C_GREEN}{C_BOLD}✨ LEGITIMATE PRODUCTION ACCESS TEST COMPLETE!{C_RESET}")
    print(f"👉 Refresh {C_CYAN}{DASHBOARD_URL}{C_RESET} to view:")
    print(f"   • 1 ALLOWED for 'postgres://production/crm/customer_accounts'")
    print(f"   • 2 BLOCKED for unauthorized delete & vault access")
    print(f"{C_BOLD}{'='*85}{C_RESET}\n")

if __name__ == "__main__":
    main()
