//! HTML page structure for the Peitho Community developer dashboard.
//! Pure monochrome design with selective Red/Green for main security actions.

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
                    <span class="badge-outline mono">LOCAL INSTANCE ●</span>
                    <span class="badge-outline text-[10px] text-dim mono">DEMO DATA</span>
                </div>
                <div class="flex items-center gap-3 text-[11px] text-dim mono mt-0.5">
                    <span>UI <span class="text-main">127.0.0.1:4040</span></span>
                    <span>•</span>
                    <span>MCP <span class="text-main">127.0.0.1:4040/mcp</span></span>
                </div>
            </div>
        </div>
        <div class="flex items-center space-x-2 text-xs mono">
            <button onclick="runSelfTest('valid_authorization')" class="btn-mono btn-allow">⚡ Simulate Allow</button>
            <button onclick="runSelfTest('unauthorized_tool')" class="btn-mono btn-deny">🛡️ Simulate Block</button>
            <button id="theme-toggle-btn" onclick="toggleTheme()" class="btn-mono">🌙 Theme</button>
        </div>
    </header>

    <!-- Nav Tabs (Simplified 3-Tab Architecture) -->
    <nav class="border-b-subtle bg-surface px-6 flex space-x-1 text-xs mono">
        <button id="tab-btn-activity" onclick="switchTab('activity')" class="tab-btn active">Activity Stream</button>
        <button id="tab-btn-capabilities" onclick="switchTab('capabilities')" class="tab-btn">Capabilities & Tokens</button>
        <button id="tab-btn-invariants" onclick="switchTab('invariants')" class="tab-btn">Security Invariants & System</button>
    </nav>

    <!-- Main Content Container -->
    <main class="p-6 max-w-7xl mx-auto w-full flex-1 space-y-6">
        <!-- 1. ACTIVITY STREAM (DEFAULT HOME) -->
        <section id="sec-activity" class="space-y-6">
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono font-bold">AUTHORIZATIONS</span>
                    <div class="text-3xl font-bold text-main mono" id="stat-auth-count">0</div>
                    <p class="text-xs text-allow mono font-bold" id="stat-auth-sub">0 ALLOW</p>
                </div>
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono font-bold">DENIED REQUESTS</span>
                    <div class="text-3xl font-bold text-main mono" id="stat-denied-count">0</div>
                    <p class="text-xs text-deny mono font-bold" id="stat-denied-sub">0 BLOCKED</p>
                </div>
                <div class="card-box space-y-1">
                    <span class="text-[11px] text-dim mono font-bold">OBSERVED LATENCY</span>
                    <div class="text-3xl font-bold text-main mono" id="stat-latency-val">—</div>
                    <p class="text-xs text-dim mono" id="stat-latency-sub">p50 · 0 evaluations (Local runtime)</p>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                <div class="lg:col-span-7 card-box space-y-4">
                    <div class="flex flex-wrap items-center justify-between gap-3 border-b-subtle pb-3">
                        <h3 class="text-xs font-bold text-main uppercase mono">SECURITY EVENT STREAM</h3>
                        <div class="flex items-center space-x-1">
                            <button onclick="setFilter('ALL')" class="pill-btn active" id="filter-btn-ALL">ALL</button>
                            <button onclick="setFilter('ALLOW')" class="pill-btn" id="filter-btn-ALLOW">ALLOW</button>
                            <button onclick="setFilter('DENY')" class="pill-btn" id="filter-btn-DENY">DENY</button>
                        </div>
                    </div>
                    <div class="scroll-box border-subtle rounded">
                        <table class="table-mono w-full text-left mono">
                            <thead class="sticky top-0 bg-surface z-10"><tr><th>TIME</th><th>RESULT</th><th>PRINCIPAL</th><th>TOOL</th><th>INVARIANT</th></tr></thead>
                            <tbody id="activity-tbody"></tbody>
                        </table>
                    </div>
                </div>
                <div class="lg:col-span-5 card-box space-y-4 sticky top-6 scroll-box">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-2">EVENT FORENSICS & INSPECTOR</h3>
                    <div id="activity-detail-container" class="mono text-xs space-y-3"></div>
                </div>
            </div>
        </section>

        <!-- 2. CAPABILITIES & TOKENS -->
        <section id="sec-capabilities" class="hidden space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                <div class="lg:col-span-6 card-box space-y-4">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-2">CAPABILITY DELEGATION TREE</h3>
                    <div id="tree-nodes-list" class="space-y-2 mono text-xs scroll-box max-h-[300px]"></div>
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-2 pt-2">CONNECTED MCP TOOLS</h3>
                    <div id="tools-list-container" class="space-y-2 mono text-xs scroll-box max-h-[220px]"></div>
                </div>
                <div class="lg:col-span-6 card-box space-y-4">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-2">TOKEN REGISTRY</h3>
                    <div id="tokens-table-container" class="scroll-box max-h-[260px]"></div>
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-2 pt-2">CAPABILITY INSPECTOR</h3>
                    <div id="tree-detail-panel" class="mono text-xs space-y-3 scroll-box max-h-[260px]"></div>
                </div>
            </div>
        </section>

        <!-- 3. SECURITY INVARIANTS & SYSTEM -->
        <section id="sec-invariants" class="hidden space-y-6">
            <div class="card-box space-y-4">
                <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-2">FORMAL SECURITY INVARIANTS REGISTRY (P-001 TO P-018)</h3>
                <div id="invariants-grid-container" class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs mono"></div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div class="card-box space-y-2">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-1">RUNTIME</h3>
                    <div id="sys-runtime" class="space-y-1 mono text-xs text-sub"></div>
                </div>
                <div class="card-box space-y-2">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-1">CRYPTO</h3>
                    <div id="sys-crypto" class="space-y-1 mono text-xs text-sub"></div>
                </div>
                <div class="card-box space-y-2">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-1">PERSISTENCE</h3>
                    <div id="sys-persistence" class="space-y-1 mono text-xs text-sub"></div>
                </div>
                <div class="card-box space-y-2">
                    <h3 class="text-xs font-bold text-main uppercase mono border-b-subtle pb-1">NETWORK</h3>
                    <div id="sys-network" class="space-y-1 mono text-xs text-sub"></div>
                </div>
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
