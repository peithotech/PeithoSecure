#!/usr/bin/env python3
"""
Test script to send real MCP JSON-RPC requests to PeithoSecure Gateway (http://127.0.0.1:8080/mcp).
Demonstrates:
1. Unauthenticated request -> Blocked (No token)
2. Valid post-quantum capability token -> Allowed
3. Scope violation / privilege escalation attempt -> Blocked
"""

import json
import urllib.request
import urllib.error
import time

GATEWAY_URL = "http://127.0.0.1:8080/mcp"
SAMPLE_TOKEN_URL = "http://127.0.0.1:8080/api/sample-token"

def get_sample_token():
    req = urllib.request.Request(SAMPLE_TOKEN_URL)
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        return data["token_hex"]

def send_mcp_call(tool_name: str, token_hex: str = None, caller_name: str = "Live-Agent-Client"):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {"query": "AAPL quarterly revenue"}
        }
    }
    data = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": caller_name,
    }
    if token_hex:
        headers["X-Peitho-Capability"] = token_hex

    req = urllib.request.Request(GATEWAY_URL, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode())
            print(f"✅ [{caller_name}] {tool_name} -> ALLOWED (HTTP {resp.status}) Response: {body}")
            return body
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        print(f"🛡️ [{caller_name}] {tool_name} -> BLOCKED (HTTP {e.code}) Response: {body}")
        return body

if __name__ == "__main__":
    print("\n🚀 --- TESTING LIVE PEITHO GATEWAY (http://127.0.0.1:8080/mcp) ---")
    
    # 1. Unauthenticated call (No Token)
    print("\n1️⃣  Sending tool call WITHOUT capability token...")
    send_mcp_call("fetch_market_data", token_hex=None, caller_name="Unauthenticated-Agent")
    time.sleep(0.5)

    # 2. Authenticated call with valid token
    print("\n2️⃣  Fetching real signed capability token and calling authorized tool...")
    token = get_sample_token()
    send_mcp_call("fetch_data", token_hex=token, caller_name="Authorized-Research-Agent")
    time.sleep(0.5)

    # 3. Privilege Escalation / Unauthorized tool call
    print("\n3️⃣  Attempting to invoke unauthorized tool with restricted token...")
    send_mcp_call("execute_unauthorized_action", token_hex=token, caller_name="Compromised-Agent")
    time.sleep(0.5)

    print("\n✨ Done! Check your browser tab at http://127.0.0.1:8080 to see these live events recorded in the table!\n")
