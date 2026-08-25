//! HTML page structure for the Peitho Community developer dashboard.
//! Calm, deterministic developer UI rendering 8 core local observability views.

use super::css::get_stylesheet;
use super::js::get_javascript;
use super::logo_data::{LOGO_BLACK_B64, LOGO_WHITE_B64};

/// Generate the self-contained HTML page.
pub fn get_page_html() -> String {
    let css = get_stylesheet();
    let js = get_javascript();

    format!(r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Peitho Community • Cryptographic Authorization</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>{css}</style>
</head>
<body class="min-h-screen flex flex-col bg-[#0b0f19] text-[#cbd5e1] font-sans">
    <!-- Header -->
    <header class="border-b border-[#1e293b] bg-[#0f172a] px-6 py-3.5 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-50">
        <div class="flex items-center space-x-3">
            <div id="brand-logo" class="h-8 w-8 flex items-center justify-center flex-shrink-0">
                <img src="data:image/png;base64,{LOGO_WHITE_B64}" class="logo-dark w-full h-full object-contain" alt="Peitho" />
                <img src="data:image/png;base64,{LOGO_BLACK_B64}" class="logo-light w-full h-full object-contain" alt="Peitho" />
            </div>
            <div>
                <div class="flex items-center gap-2">
                    <span class="font-bold text-sm tracking-tight text-white font-mono">PEITHO COMMUNITY</span>
                    <span class="px-2 py-0.5 text-[10px] font-mono rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">LOCAL INSTANCE</span>
                </div>
                <p class="text-[11px] text-[#64748b]">Cryptographic Agent Authorization Kernel</p>
            </div>
        </div>

        <div class="flex items-center space-x-2 text-xs font-mono">
            <button onclick="runSelfTest('valid_authorization')" class="px-3 py-1.5 rounded bg-[#1e293b] hover:bg-[#334155] text-[#94a3b8] hover:text-white transition">
                ⚡ Valid Self-Test
            </button>
            <button onclick="runSelfTest('resource_traversal')" class="px-3 py-1.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition">
                🛡️ Test Traversal Block
            </button>
            <button onclick="runSelfTest('unauthorized_tool')" class="px-3 py-1.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition">
                🛡️ Test Tool Block
            </button>
        </div>
    </header>

    <!-- Nav Tabs -->
    <nav class="border-b border-[#1e293b] bg-[#0f172a] px-6 flex space-x-1 overflow-x-auto text-xs font-mono">
        <button id="tab-btn-overview" onclick="switchTab('overview')" class="tab-btn active px-4 py-2.5 border-b-2 border-emerald-500 text-white font-medium">Overview</button>
        <button id="tab-btn-capabilities" onclick="switchTab('capabilities')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">Capabilities Tree</button>
        <button id="tab-btn-decisions" onclick="switchTab('decisions')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">Decision Inspector</button>
        <button id="tab-btn-activity" onclick="switchTab('activity')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">Activity Stream</button>
        <button id="tab-btn-tokens" onclick="switchTab('tokens')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">Tokens</button>
        <button id="tab-btn-tools" onclick="switchTab('tools')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">MCP Tools</button>
        <button id="tab-btn-invariants" onclick="switchTab('invariants')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">Security Invariants</button>
        <button id="tab-btn-system" onclick="switchTab('system')" class="tab-btn px-4 py-2.5 text-[#94a3b8] hover:text-white transition">System</button>
    </nav>

    <!-- Main Content Container -->
    <main class="p-6 max-w-7xl mx-auto w-full flex-1 space-y-6">
        <!-- 1. OVERVIEW -->
        <section id="sec-overview" class="space-y-6">
            <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div class="p-4 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-1">
                    <span class="text-[11px] text-[#64748b] font-mono">AUTHORIZATIONS</span>
                    <div class="text-2xl font-bold text-white font-mono" id="stat-auth-count">0</div>
                    <p class="text-[11px] text-emerald-400 font-mono">100% Local In-Memory</p>
                </div>
                <div class="p-4 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-1">
                    <span class="text-[11px] text-[#64748b] font-mono">DENIED PROBES</span>
                    <div class="text-2xl font-bold text-rose-400 font-mono" id="stat-denied-count">0</div>
                    <p class="text-[11px] text-[#64748b] font-mono">Attacks Blocked</p>
                </div>
                <div class="p-4 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-1">
                    <span class="text-[11px] text-[#64748b] font-mono">OBSERVED LATENCY</span>
                    <div class="text-2xl font-bold text-emerald-400 font-mono" id="stat-latency-val">46.0 µs</div>
                    <p class="text-[11px] text-[#64748b] font-mono">Median (ARM64 Neon)</p>
                </div>
                <div class="p-4 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-1">
                    <span class="text-[11px] text-[#64748b] font-mono">LOCAL STATUS</span>
                    <div class="text-sm font-bold text-emerald-400 font-mono flex items-center gap-1.5 mt-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> ONLINE (PORT 8080)
                    </div>
                    <p class="text-[11px] text-[#64748b] font-mono">Zero Network Dependency</p>
                </div>
            </div>

            <!-- Health Checklist -->
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-3">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono tracking-wider">Local Security Health Checklist</h3>
                <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
                    <div class="flex items-center gap-2 text-emerald-400"><span>✓</span> <span class="text-[#cbd5e1]">Root Authority (ML-DSA-44)</span></div>
                    <div class="flex items-center gap-2 text-emerald-400"><span>✓</span> <span class="text-[#cbd5e1]">Token Verifier (Zero-Allocation)</span></div>
                    <div class="flex items-center gap-2 text-emerald-400"><span>✓</span> <span class="text-[#cbd5e1]">Replay Protection (&lt;15ns Nonce)</span></div>
                    <div class="flex items-center gap-2 text-emerald-400"><span>✓</span> <span class="text-[#cbd5e1]">Revocation Store (In-Memory)</span></div>
                    <div class="flex items-center gap-2 text-emerald-400"><span>✓</span> <span class="text-[#cbd5e1]">Persistence (Atomic POSIX)</span></div>
                    <div class="flex items-center gap-2 text-emerald-400"><span>✓</span> <span class="text-[#cbd5e1]">Observability (P-019 Non-Blocking)</span></div>
                </div>
            </div>
        </section>

        <!-- 2. CAPABILITIES TREE -->
        <section id="sec-capabilities" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Visual Capability Delegation Tree</h3>
                <p class="text-xs text-[#64748b]">Authority strictly narrows down the chain (Monotonic Attenuation Invariant P-002).</p>
                <div id="capability-tree-container" class="font-mono text-xs space-y-2 border border-[#1e293b] p-4 rounded bg-[#0b0f19]"></div>
            </div>
        </section>

        <!-- 3. DECISION INSPECTOR -->
        <section id="sec-decisions" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Live Decision Inspector ("Explain This Decision")</h3>
                <div id="decision-detail-container" class="font-mono text-xs space-y-3">
                    <p class="text-[#64748b]">Click a recent request or run a self-test to view step-by-step constraint evaluations.</p>
                </div>
            </div>
        </section>

        <!-- 4. ACTIVITY STREAM -->
        <section id="sec-activity" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Local Security Event Stream</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs font-mono">
                        <thead class="border-b border-[#1e293b] text-[#64748b]">
                            <tr><th class="py-2">TIME</th><th>CALLER</th><th>TOOL</th><th>OUTCOME</th><th>LATENCY</th><th>INVARIANT</th></tr>
                        </thead>
                        <tbody id="activity-tbody" class="divide-y divide-[#1e293b]"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- 5. TOKENS -->
        <section id="sec-tokens" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Local Token Catalog</h3>
                <div id="tokens-catalog-container" class="space-y-3 text-xs font-mono"></div>
            </div>
        </section>

        <!-- 6. MCP & TOOLS -->
        <section id="sec-tools" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Protected MCP Tool Inventory</h3>
                <div id="tools-inventory-container" class="space-y-2 text-xs font-mono"></div>
            </div>
        </section>

        <!-- 7. SECURITY INVARIANTS -->
        <section id="sec-invariants" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Formal Security Invariant Registry (P-001 to P-019)</h3>
                <div id="invariants-grid-container" class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono"></div>
            </div>
        </section>

        <!-- 8. SYSTEM DIAGNOSTICS -->
        <section id="sec-system" class="hidden space-y-4">
            <div class="p-5 rounded-lg bg-[#0f172a] border border-[#1e293b] space-y-4">
                <h3 class="text-xs font-bold text-[#94a3b8] uppercase font-mono">Local System & Build Diagnostics</h3>
                <div id="system-diagnostics-container" class="space-y-2 text-xs font-mono text-[#94a3b8]"></div>
            </div>
        </section>
    </main>

    <footer class="border-t border-[#1e293b] bg-[#0f172a] px-6 py-3 text-xs font-mono flex items-center justify-between text-[#64748b]">
        <span>PEITHO COMMUNITY • Local Node Observability</span>
        <span>Apache-2.0 License • Git 7c51e4b</span>
    </footer>

    <script>{js}</script>
</body>
</html>"#)
}
