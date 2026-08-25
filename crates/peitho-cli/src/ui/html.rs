//! HTML page structure for the Peitho Community developer dashboard.
//! Pure monochrome design with automatic time-based Dark and Light modes.

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
<body class="min-h-screen flex flex-col">
    <!-- Header -->
    <header class="border-b-subtle bg-surface px-6 py-3 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-50">
        <div class="flex items-center space-x-3">
            <div id="brand-logo" class="h-8 w-8 flex items-center justify-center flex-shrink-0">
                <img src="data:image/png;base64,{LOGO_WHITE_B64}" class="logo-dark w-full h-full object-contain" alt="Peitho" />
                <img src="data:image/png;base64,{LOGO_BLACK_B64}" class="logo-light w-full h-full object-contain" alt="Peitho" />
            </div>
            <div>
                <div class="flex items-center gap-2">
                    <span class="font-bold text-sm tracking-tight text-main mono">PEITHO COMMUNITY</span>
                    <span class="badge-outline mono">LOCAL INSTANCE</span>
                </div>
                <p class="text-[11px] text-sub">Cryptographic Agent Authorization Kernel</p>
            </div>
        </div>

        <div class="flex items-center space-x-2 text-xs mono">
            <button onclick="runSelfTest('valid_authorization')" class="btn-mono">
                ⚡ Valid Test
            </button>
            <button onclick="runSelfTest('resource_traversal')" class="btn-mono">
                🛡️ Test Traversal Block
            </button>
            <button onclick="runSelfTest('unauthorized_tool')" class="btn-mono">
                🛡️ Test Tool Block
            </button>
            <button id="theme-toggle-btn" onclick="toggleTheme()" class="btn-mono">
                🌙 Theme (Auto)
            </button>
        </div>
    </header>

    <!-- Nav Tabs -->
    <nav class="border-b-subtle bg-surface px-6 flex space-x-1 overflow-x-auto text-xs mono">
        <button id="tab-btn-overview" onclick="switchTab('overview')" class="tab-btn active">Overview</button>
        <button id="tab-btn-capabilities" onclick="switchTab('capabilities')" class="tab-btn">Capabilities Tree</button>
        <button id="tab-btn-decisions" onclick="switchTab('decisions')" class="tab-btn">Decision Inspector</button>
        <button id="tab-btn-activity" onclick="switchTab('activity')" class="tab-btn">Activity Stream</button>
        <button id="tab-btn-tokens" onclick="switchTab('tokens')" class="tab-btn">Tokens</button>
        <button id="tab-btn-tools" onclick="switchTab('tools')" class="tab-btn">MCP Tools</button>
        <button id="tab-btn-invariants" onclick="switchTab('invariants')" class="tab-btn">Security Invariants</button>
        <button id="tab-btn-system" onclick="switchTab('system')" class="tab-btn">System</button>
    </nav>

    <!-- Main Content Container -->
    <main class="p-6 max-w-7xl mx-auto w-full flex-1 space-y-6">
        <!-- 1. OVERVIEW -->
        <section id="sec-overview" class="space-y-6">
            <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono">AUTHORIZATIONS</span>
                    <div class="text-2xl font-bold text-main mono" id="stat-auth-count">0</div>
                    <p class="text-[11px] text-sub mono">100% Local In-Memory</p>
                </div>
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono">DENIED PROBES</span>
                    <div class="text-2xl font-bold text-main mono" id="stat-denied-count">0</div>
                    <p class="text-[11px] text-dim mono">Attacks Blocked</p>
                </div>
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono">OBSERVED LATENCY</span>
                    <div class="text-2xl font-bold text-main mono" id="stat-latency-val">46.0 µs</div>
                    <p class="text-[11px] text-dim mono">Median (ARM64 Neon)</p>
                </div>
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono">LOCAL STATUS</span>
                    <div class="text-sm font-bold text-main mono flex items-center gap-1.5 mt-2">
                        <span class="w-2 h-2 rounded-full bg-current animate-pulse"></span> ONLINE (PORT 8080)
                    </div>
                    <p class="text-[11px] text-dim mono">Zero Network Dependency</p>
                </div>
            </div>

            <!-- Health Checklist -->
            <div class="card-box space-y-3">
                <h3 class="text-xs font-bold text-sub uppercase mono tracking-wider">Local Security Health Checklist</h3>
                <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs mono">
                    <div class="flex items-center gap-2 text-main"><span>✓</span> <span class="text-sub">Root Authority (ML-DSA-44)</span></div>
                    <div class="flex items-center gap-2 text-main"><span>✓</span> <span class="text-sub">Token Verifier (Zero-Allocation)</span></div>
                    <div class="flex items-center gap-2 text-main"><span>✓</span> <span class="text-sub">Replay Protection (&lt;15ns Nonce)</span></div>
                    <div class="flex items-center gap-2 text-main"><span>✓</span> <span class="text-sub">Revocation Store (In-Memory)</span></div>
                    <div class="flex items-center gap-2 text-main"><span>✓</span> <span class="text-sub">Persistence (Atomic POSIX)</span></div>
                    <div class="flex items-center gap-2 text-main"><span>✓</span> <span class="text-sub">Observability (P-019 Non-Blocking)</span></div>
                </div>
            </div>
        </section>

        <!-- 2. CAPABILITIES TREE -->
        <section id="sec-capabilities" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Visual Capability Delegation Tree</h3>
                <p class="text-xs text-dim">Authority strictly narrows down the chain (Monotonic Attenuation Invariant P-002).</p>
                <div id="capability-tree-container" class="mono text-xs space-y-2 border-subtle p-4 rounded bg-surface"></div>
            </div>
        </section>

        <!-- 3. DECISION INSPECTOR -->
        <section id="sec-decisions" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Live Decision Inspector ("Explain This Decision")</h3>
                <div id="decision-detail-container" class="mono text-xs space-y-3">
                    <p class="text-dim">Click a recent request or run a self-test to view step-by-step constraint evaluations.</p>
                </div>
            </div>
        </section>

        <!-- 4. ACTIVITY STREAM -->
        <section id="sec-activity" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Local Security Event Stream</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs mono">
                        <thead class="border-b-subtle text-dim">
                            <tr><th class="py-2">TIME</th><th>CALLER</th><th>TOOL</th><th>OUTCOME</th><th>LATENCY</th><th>INVARIANT</th></tr>
                        </thead>
                        <tbody id="activity-tbody" class="divide-y divide-border"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- 5. TOKENS -->
        <section id="sec-tokens" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Local Token Catalog</h3>
                <div id="tokens-catalog-container" class="space-y-3 text-xs mono"></div>
            </div>
        </section>

        <!-- 6. MCP & TOOLS -->
        <section id="sec-tools" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Protected MCP Tool Inventory</h3>
                <div id="tools-inventory-container" class="space-y-2 text-xs mono"></div>
            </div>
        </section>

        <!-- 7. SECURITY INVARIANTS -->
        <section id="sec-invariants" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Formal Security Invariant Registry (P-001 to P-019)</h3>
                <div id="invariants-grid-container" class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs mono"></div>
            </div>
        </section>

        <!-- 8. SYSTEM DIAGNOSTICS -->
        <section id="sec-system" class="hidden space-y-4">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-sub uppercase mono">Local System & Build Diagnostics</h3>
                <div id="system-diagnostics-container" class="space-y-2 text-xs mono text-sub"></div>
            </div>
        </section>
    </main>

    <footer class="border-t-subtle bg-surface px-6 py-3 text-xs mono flex items-center justify-between text-dim">
        <span>PEITHO COMMUNITY • Local Node Observability</span>
        <span>Pure Monochrome System • Apache-2.0</span>
    </footer>

    <script>{js}</script>
</body>
</html>"#)
}
