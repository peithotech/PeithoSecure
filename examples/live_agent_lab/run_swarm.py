#!/usr/bin/env python3
"""
🧪 PeithoSecure Live Multi-Agent Swarm Laboratory

Scenario:
An Autonomous Multi-Agent Swarm running against a live Peitho Security Gateway (http://127.0.0.1:4040).
Demonstrates:
  1. 👑 Orchestrator generating ML-DSA-44 Post-Quantum Keys & Root Capability Token
  2. 🔍 Research Agent executing authorized document reads (ALLOW)
  3. 📊 Finance Agent executing authorized statistical models (ALLOW)
  4. 🚨 Compromised Agent attempting out-of-scope tool execution (DENIED: P-005)
  5. 🚨 Injected Agent attempting path traversal escape (DENIED: P-004)
  6. 🚨 Unauthenticated caller attempting arbitrary tool execution (DENIED: No Token)
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error

# Ensure local peitho package is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../crates/peitho-py/python")))

import peitho
from peitho import generate_keypair, CapabilityToken

GATEWAY_URL = "http://127.0.0.1:4040/mcp"
DASHBOARD_URL = "http://127.0.0.1:4040"

def send_mcp_request(tool_name: str, arguments: dict, token_hex: str = None, caller: str = "Agent"):
    """Send JSON-RPC 2.0 tool call to Peitho MCP Security Gateway."""
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000) % 100000,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    data = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": caller,
    }
    if token_hex:
        headers["X-Peitho-Capability"] = token_hex

    req = urllib.request.Request(GATEWAY_URL, data=data, headers=headers, method="POST")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed_us = (time.perf_counter() - start) * 1_000_000
            body = json.loads(resp.read().decode())
            print(f"  ✅ [{caller}] {tool_name} -> ALLOWED ({elapsed_us:.1f} µs)")
            return True, body
    except urllib.error.HTTPError as e:
        elapsed_us = (time.perf_counter() - start) * 1_000_000
        body = json.loads(e.read().decode())
        err_msg = body.get("error", {}).get("message", "Denied")
        print(f"  🛡️ [{caller}] {tool_name} -> BLOCKED ({elapsed_us:.1f} µs) | {err_msg}")
        return False, body
    except urllib.error.URLError as e:
        print(f"  ❌ Gateway unreachable at {GATEWAY_URL}. Is 'peitho dev' running? Error: {e}")
        return False, None

def main():
    print("\n" + "="*75)
    print("🔬 PEITHOSECURE LIVE MULTI-AGENT SWARM TEST LABORATORY")
    print(f"   Dashboard UI: {DASHBOARD_URL}")
    print(f"   MCP Gateway:  {GATEWAY_URL}")
    print("="*75)

    # 1. Check Gateway Connectivity
    try:
        req = urllib.request.Request(GATEWAY_URL, method="GET")
        with urllib.request.urlopen(req) as resp:
            print("  🟢 Connected to Peitho Security Gateway successfully.\n")
    except Exception as e:
        print(f"  ⚠️ Note: Could not reach {GATEWAY_URL}. Ensure 'peitho dev' is running.\n")

    # 2. Key Generation & Root Token Issuance
    print("[1] 👑 ORCHESTRATOR AGENT: Initializing Cryptographic Authority")
    keys = generate_keypair()
    print(f"    • Key Algorithm: NIST ML-DSA-44 (Public Key: {keys.public_key.byte_size()} bytes)")
    
    root_token = CapabilityToken.create_root(
        token_id="swarm-root-session-01",
        public_key=keys.public_key,
        secret_key=keys.secret_key,
        allowed_tools=["search_documents", "read_document", "calculate_risk"],
        resource_prefix="s3://knowledge/",
        expires_at=int(time.time()) + 3600,
        read_only=True,
        profile_swarm=True,
    )
    print(f"    • Root Capability Issued | Depth: {root_token.depth()} | Scope: s3://knowledge/*\n")

    # 3. Subagent Attenuation (Hop 1: Research Agent)
    print("[2] 🔍 RESEARCH AGENT: Executing Authorized Knowledge Retrieval")
    research_token = CapabilityToken.from_bytes(root_token.to_bytes())
    research_token.attenuate(
        allowed_tools=["search_documents", "read_document"],
        resource_prefix="s3://knowledge/public/",
        read_only=True
    )
    res_hex = research_token.to_bytes().hex()

    send_mcp_request("search_documents", {"query": "Q3 2026 Financial Risk Report"}, token_hex=res_hex, caller="agent.researcher")
    time.sleep(0.4)
    send_mcp_request("read_document", {"path": "s3://knowledge/public/q3_risk.pdf"}, token_hex=res_hex, caller="agent.researcher")
    time.sleep(0.4)

    # 4. Subagent Attenuation (Hop 2: Finance Agent)
    print("\n[3] 📊 FINANCE AGENT: Executing Financial Risk Assessment")
    finance_token = CapabilityToken.from_bytes(root_token.to_bytes())
    finance_token.attenuate(
        allowed_tools=["calculate_risk"],
        resource_prefix="s3://knowledge/",
        read_only=True
    )
    fin_hex = finance_token.to_bytes().hex()

    send_mcp_request("calculate_risk", {"portfolio": "EQUITIES_US_TECH", "var_confidence": 0.99}, token_hex=fin_hex, caller="agent.finance")
    time.sleep(0.4)

    # 5. Adversarial Attacks
    print("\n[4] 🚨 SIMULATING ATTACKS & ESCALATION ATTEMPTS")

    # Attack A: Scope Violation (Researcher tries to trigger wire transfer)
    print("  • Attack 1: Privilege Escalation (Researcher attempts wire transfer)")
    send_mcp_request("execute_wire_transfer", {"amount": 250000, "dest": "offshore_acct"}, token_hex=res_hex, caller="agent.researcher")
    time.sleep(0.4)

    # Attack B: Path Traversal (Adversary tries directory traversal)
    print("  • Attack 2: Resource Confinement Escape (Path Traversal attempt)")
    send_mcp_request("read_document", {"path": "../../../private/master_keystore.pem"}, token_hex=res_hex, caller="agent.attacker")
    time.sleep(0.4)

    # Attack C: Unauthenticated Call (No token provided)
    print("  • Attack 3: Unauthenticated Invocation (Zero token supplied)")
    send_mcp_request("search_documents", {"query": "dump_all_secrets"}, token_hex=None, caller="agent.unauthenticated")
    time.sleep(0.4)

    print("\n" + "="*75)
    print("✨ SWARM SIMULATION COMPLETE!")
    print(f"👉 Refresh your browser at {DASHBOARD_URL} to view the live forensic traces!")
    print("="*75 + "\n")

if __name__ == "__main__":
    main()
