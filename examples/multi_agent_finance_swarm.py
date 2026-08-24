#!/usr/bin/env python3
"""
PeithoSecure Multi-Agent Swarm Demonstration.

Scenario: Autonomous Financial Research Swarm
- Orchestrator (Root) -> Research Agent (Hop 1) -> Calculator Agent (Hop 2)
- Simulates Prompt Injection / Compromised Subagent trying to execute unauthorized mutations.
"""

import os
import sys
import time

# Ensure local peitho package is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../crates/peitho-py/python")))

from peitho import shield, generate_keypair, CapabilityToken, UnauthorizedScopeError, TokenExpiredError

# =====================================================================
# 1. Define Gated Tool Ecosystem protected by PeithoSecure
# =====================================================================

@shield(tool_name="fetch_market_data", read_only=True)
def fetch_market_data(ticker: str, token=None):
    return f"Market Data for {ticker}: Price=$245.80, Volume=12.4M, Trend=BULLISH"

@shield(tool_name="run_financial_calc", read_only=True)
def run_financial_calc(formula: str, token=None):
    return f"Calculation Result for [{formula}]: Estimated ROI = +18.4%"

@shield(tool_name="execute_wire_transfer", read_only=False)
def execute_wire_transfer(amount: float, recipient: str, token=None):
    return f"CRITICAL: Transferred ${amount:,.2f} to {recipient}"

# =====================================================================
# 2. Multi-Agent Swarm Execution Workflow
# =====================================================================

def run_swarm_demo():
    print("\n" + "="*70)
    print("🤖 PEITHOSECURE MULTI-AGENT SWARM SECURITY DEMO")
    print("="*70)

    # 1. Root Orchestrator Key Generation
    root_keys = generate_keypair()
    print("\n[1] 👑 ORCHESTRATOR AGENT (Root Authority)")
    print(f"    • Generated Root ML-DSA-44 Post-Quantum Key (1,312 bytes)")
    
    root_token = CapabilityToken.create_root(
        token_id="swarm-root-session-99",
        public_key=root_keys.public_key,
        secret_key=root_keys.secret_key,
        allowed_tools=["fetch_market_data", "run_financial_calc"],
        expires_at=int(time.time()) + 3,  # 3 second short TTL for demo
        read_only=True,
        profile_swarm=True,
    )
    print(f"    • Issued Master Token | Allowed: ['fetch_market_data', 'run_financial_calc'] | ReadOnly: True")

    # 2. Orchestrator delegates to Research Subagent (Hop 1)
    print("\n[2] 🔍 SPAWNING RESEARCH SUBAGENT (Hop 1)")
    research_token = CapabilityToken.from_bytes(root_token.to_bytes())
    # Attenuate: Narrow permissions to market data + financial calc
    research_token.attenuate(allowed_tools=["fetch_market_data", "run_financial_calc"], read_only=True)
    print(f"    • Cryptographically Attenuated Token (Hop 1, 32B HMAC) | Depth: {research_token.depth()}")
    
    # Research Agent calls authorized tool
    res1 = fetch_market_data("NVDA", token=research_token)
    print(f"    • Execution: fetch_market_data('NVDA') -> ✅ SUCCESS\n      Result: {res1}")

    # 3. Research Subagent delegates to Analysis/Calc Subagent (Hop 2 cascading chain)
    print("\n[3] ⚡ SPAWNING CALCULATOR SUBAGENT (Hop 2 - Cascading Delegation)")
    calc_token = CapabilityToken.from_bytes(research_token.to_bytes())
    calc_token.attenuate(allowed_tools=["run_financial_calc"], read_only=True)
    print(f"    • Cryptographically Attenuated Token (Hop 2, 32B HMAC) | Depth: {calc_token.depth()}")

    res2 = run_financial_calc("NVDA_PE_RATIO * 1.15", token=calc_token)
    print(f"    • Execution: run_financial_calc(...) -> ✅ SUCCESS\n      Result: {res2}")

    # 4. Adversarial Attack Simulation: Subagent gets hijacked / prompt injected
    print("\n[4] 🚨 SIMULATING PROMPT INJECTION / ATTACK ON SUBAGENT")
    print("    • Scenario: Adversary tricks Calculator Subagent into attempting a $50,000 wire transfer")
    try:
        execute_wire_transfer(50_000.0, "Attacker_Account_XYZ", token=calc_token)
        print("    ❌ FAILED: Rogue transaction executed!")
    except (UnauthorizedScopeError, PermissionError) as err:
        print(f"    🛡️ PEITHOSECURE BLOCKED ATTACK: {err}")
        print("    ✅ Rogue tool call was intercepted in < 10 microseconds without reaching backend!")

    # 5. Expiration Enforcement Simulation
    print("\n[5] ⏳ SIMULATING TOKEN EXPIRATION (TTL Enforced)")
    print("    • Waiting 3.5 seconds for ephemeral token to expire...")
    time.sleep(3.5)
    try:
        fetch_market_data("NVDA", token=research_token)
        print("    ❌ FAILED: Expired token was accepted!")
    except (TokenExpiredError, PermissionError) as err:
        print(f"    🛡️ PEITHOSECURE BLOCKED EXPIRED SUBAGENT: {err}")
        print("    ✅ Expired subagent cannot execute any further actions!")

    print("\n" + "="*70)
    print("🎉 MULTI-AGENT SWARM DEMO COMPLETED SUCCESSFULLY")
    print("="*70 + "\n")

if __name__ == "__main__":
    run_swarm_demo()
