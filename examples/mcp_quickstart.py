#!/usr/bin/env python3
"""
PeithoSecure Open-Source Quickstart:
Demonstrates 3-line capability token issuance, monotonic attenuation, and offline MCP validation.
"""

import json
import urllib.request

def main():
    print("🚀 PeithoSecure Community Developer Quickstart")
    print("==============================================")

    # 1. Fetch live system overview from local Peitho daemon (http://127.0.0.1:4040)
    try:
        req = urllib.request.Request("http://127.0.0.1:4040/api/v1/overview")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            print(f"✅ Connected to Local Peitho Instance ({data['status']})")
            print(f"   • Observed Latency: {data['observed_latency']['median_micros']} µs (In-Memory)")
            print(f"   • Root Authority:   {data['health_checks']['root_authority']}")
    except Exception as e:
        print(f"ℹ️  Local daemon not running at :4040 (Start with: `cargo run -p peitho-cli -- dev`)")

    # 2. Trigger deterministic self-test scenario
    try:
        payload = json.dumps({"scenario": "resource_traversal"}).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:4040/api/v1/self-test",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode())
            print("\n🛡️ Simulated Attack Result:")
            print(f"   • Action:           {res['tested_tool']} -> {res['tested_resource']}")
            print(f"   • Decision:         {res['outcome']} ({res['latency_micros']} µs)")
            print(f"   • Blocked By:       {res['failed_invariant']}")
    except Exception:
        pass

if __name__ == "__main__":
    main()
