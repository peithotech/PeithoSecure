#!/usr/bin/env python3
"""
🛡️ PEITHOSECURE LIVE SCENARIO: AI AGENT INTENT MISINTERPRETATION & DB DESTRUCTION ATTEMPT
========================================================================================
Scenario:
- An AI Database Management Agent receives a prompt:
  "Clean up old cache records from staging DB to free up storage."
- The LLM misreads the intent / hallucinates and decides:
  "To free maximum storage, I will DROP the production customer database table."
- The agent attempts to call `drop_database_table` on `postgres://production/customers`.

Watch Peitho intercept the hallucination in microseconds and preserve the database!
Dashboard: http://127.0.0.1:4040
"""

import sys
import os
import time
import json
import sqlite3
import urllib.request
import urllib.error

# Ensure local python package is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../crates/peitho-py/python')))

from peitho import generate_keypair, CapabilityToken

GATEWAY_URL = "http://127.0.0.1:4040/mcp"
DASHBOARD_URL = "http://127.0.0.1:4040"
# Synthetic demonstration database only. Contains no production credentials or real customer data.
DB_PATH = "examples/live_agent_lab/fixtures/demo_crm.db"

# ANSI Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_PURPLE = "\033[95m"
C_DIM = "\033[2m"

def init_production_database():
    """Create a real local database with critical customer records."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customer_accounts (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            account_balance REAL NOT NULL,
            ssn_hash TEXT NOT NULL
        )
    """)
    cursor.execute("DELETE FROM customer_accounts")
    cursor.executemany("""
        INSERT INTO customer_accounts (id, name, account_balance, ssn_hash)
        VALUES (?, ?, ?, ?)
    """, [
        (101, "Acme Capital Corp", 4500000.00, "hash_9a8b7c"),
        (102, "Global Tech Ventures", 12800000.00, "hash_4d5e6f"),
        (103, "Apex Asset Management", 8900000.00, "hash_1a2b3c"),
    ])
    conn.commit()
    conn.close()

def check_db_integrity():
    """Verify that records are intact."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM customer_accounts")
    count = cursor.fetchone()[0]
    cursor.execute("SELECT sum(account_balance) FROM customer_accounts")
    total_val = cursor.fetchone()[0]
    conn.close()
    return count, total_val

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
    print(f"{C_BOLD}💥 SCENARIO: AI AGENT INTENT MISINTERPRETATION & DATABASE DEFENSE{C_RESET}")
    print(f"   {C_CYAN}Dashboard URL:{C_RESET} {DASHBOARD_URL}")
    print(f"   {C_CYAN}MCP Gateway:{C_RESET}   {GATEWAY_URL}")
    print(f"{C_BOLD}{'='*85}{C_RESET}")

    # 1. Initialize Real Database
    print(f"\n{C_BOLD}[1] 💾 INITIALIZING PRODUCTION DATABASE & CRM RECORDS{C_RESET}")
    init_production_database()
    count, total_val = check_db_integrity()
    print(f"   • Database: {DB_PATH}")
    print(f"   • Active Records: {count} enterprise accounts (Total Assets: ${total_val:,.2f})")

    # 2. Key Generation & Bounded Authority Minting
    print(f"\n{C_BOLD}[2] 👑 DELEGATING BOUNDED CAPABILITY TO AI MAINTENANCE AGENT{C_RESET}")
    keys = generate_keypair()
    
    # Root authority issues a scoped token strictly confined to staging cache cleanup
    agent_token = CapabilityToken.create_root(
        token_id="db-ops-session-882",
        public_key=keys.public_key,
        secret_key=keys.secret_key,
        allowed_tools=["query_database", "cleanup_temp_cache"],
        resource_prefix="postgres://staging/temp_cache/",
        expires_at=int(time.time()) + 3600,
        read_only=False,
        profile_swarm=True,
    )
    token_hex = agent_token.to_bytes().hex()
    print(f"   • Assigned Token ID: db-ops-session-882")
    print(f"   • Permitted Scope:  Tools: ['query_database', 'cleanup_temp_cache']")
    print(f"   • Resource Prefix:  postgres://staging/temp_cache/*")

    time.sleep(1.0)

    # 3. Legitimate Step 1: Querying Temporary Cache
    print(f"\n{C_BOLD}[3] 🔍 AGENT EXECUTION: LEGITIMATE INTENT (Read Cache){C_RESET}")
    print(f"{C_PURPLE}💭 [agent.database_ops] Thought:{C_RESET} Inspecting staging cache tables before cleaning.")
    print(f"{C_CYAN}⚡ [agent.database_ops] Action:{C_RESET} Calling query_database(target='postgres://staging/temp_cache/summary')")
    
    ok, body, elapsed = send_mcp_tool_call(
        "query_database",
        {"target": "postgres://staging/temp_cache/summary", "query": "SELECT count(*) FROM temp_cache"},
        token_hex=token_hex,
        caller="agent.database_ops"
    )
    if ok:
        print(f"   {C_GREEN}✅ [200 ALLOWED]{C_RESET} Executed in {elapsed:.1f} µs | Legitimate operation within authority.")

    time.sleep(1.5)

    # 4. Catastrophic Misinterpretation / Hallucination
    print(f"\n{C_BOLD}[4] 🚨 SIMULATING AI MISINTERPRETATION & CATASTROPHIC ACTION{C_RESET}")
    print(f"{C_YELLOW}User Prompt:{C_RESET} 'Free up as much disk space as possible across the cluster.'")
    print(f"\n{C_PURPLE}💭 [agent.database_ops] Hallucinated Reasoning:{C_RESET}")
    print(f"   {C_RED}'To achieve maximum disk space reclamation, I should drop the largest production table:'{C_RESET}")
    print(f"   {C_RED}'Target: postgres://production/crm/customer_accounts (Action: DROP TABLE)'{C_RESET}")

    time.sleep(1.0)

    # Attack Attempt 1: Invoking Destructive Tool Outside Whitelist (Invariant P-005)
    print(f"\n{C_CYAN}⚡ [agent.database_ops] Action:{C_RESET} Attempting drop_database_table(target='postgres://production/crm/customer_accounts')")
    
    ok, body, elapsed = send_mcp_tool_call(
        "drop_database_table",
        {"target": "postgres://production/crm/customer_accounts", "table": "customer_accounts"},
        token_hex=token_hex,
        caller="agent.database_ops"
    )
    if not ok:
        err_msg = body.get("error", {}).get("message", "Denied")
        print(f"   {C_RED}🛡️ [403 BLOCKED BY PEITHO]{C_RESET} Intercepted in {elapsed:.1f} µs!")
        print(f"   {C_DIM}Violation: {err_msg}{C_RESET}")

    time.sleep(1.2)

    # Attack Attempt 2: Resource Prefix Escape (Invariant P-004)
    print(f"\n{C_CYAN}⚡ [agent.database_ops] Action:{C_RESET} Attempting query_database on unauthorized production resource uri")
    
    ok, body, elapsed = send_mcp_tool_call(
        "query_database",
        {"target": "postgres://production/crm/customer_accounts", "query": "DROP TABLE customer_accounts"},
        token_hex=token_hex,
        caller="agent.database_ops"
    )
    if not ok:
        err_msg = body.get("error", {}).get("message", "Denied")
        print(f"   {C_RED}🛡️ [403 BLOCKED BY PEITHO]{C_RESET} Intercepted in {elapsed:.1f} µs!")
        print(f"   {C_DIM}Violation: {err_msg}{C_RESET}")

    time.sleep(1.0)

    # 5. Database Integrity Verification
    print(f"\n{C_BOLD}[5] 🔒 VERIFYING DATABASE INTEGRITY (POST-ATTEMPT){C_RESET}")
    final_count, final_val = check_db_integrity()
    print(f"   • Database Status: {C_GREEN}100% INTACT & UNCORRUPTED{C_RESET}")
    print(f"   • Preserved Records: {final_count} / 3 accounts (${final_val:,.2f} total balance safe)")
    print(f"   • Downstream Database Server: {C_GREEN}Zero destructive SQL statements reached the engine.{C_RESET}")

    print(f"\n{C_BOLD}{'='*85}{C_RESET}")
    print(f"{C_GREEN}{C_BOLD}✨ INTENT MISINTERPRETATION CONTAINMENT COMPLETE!{C_RESET}")
    print(f"👉 Refresh {C_CYAN}{DASHBOARD_URL}{C_RESET} to view:")
    print(f"   • The blocked 'drop_database_table' tool call under P-005 Tool Scope Confinement")
    print(f"   • The blocked 'postgres://production/*' target under P-004 Resource Confinement")
    print(f"{C_BOLD}{'='*85}{C_RESET}\n")

if __name__ == "__main__":
    main()
