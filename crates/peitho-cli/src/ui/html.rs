use super::css::get_stylesheet;
use super::js::get_javascript;
use super::logo_data::{LOGO_BLACK_B64, LOGO_WHITE_B64};

/// Generate the complete self-contained HTML page.
pub fn get_page_html() -> String {
    let css = get_stylesheet();
    let js = get_javascript();

    format!(r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PeithoSecure Gateway Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>{css}</style>
</head>
<body class="min-h-screen flex flex-col">
    <!-- Header -->
    <header class="border-b-subtle bg-surface px-6 py-3.5 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-50">
        <div class="flex items-center space-x-3">
            <div id="brand-logo" class="h-8 w-8 flex items-center justify-center flex-shrink-0">
                <img src="data:image/png;base64,{LOGO_WHITE_B64}" class="logo-dark w-full h-full object-contain" alt="PeithoSecure Logo" />
                <img src="data:image/png;base64,{LOGO_BLACK_B64}" class="logo-light w-full h-full object-contain" alt="PeithoSecure Logo" />
            </div>
            <div>
                <div class="flex items-center gap-2">
                    <span class="font-bold text-sm tracking-tight text-main">PeithoSecure Gateway</span>
                    <span class="badge-outline mono">FIPS 204</span>
                </div>
                <p class="text-[11px] text-sub">Zero-Trust Cryptographic Capability Gateway for MCP</p>
            </div>
        </div>

        <div class="flex items-center space-x-3 text-xs">
            <button onclick="runCryptoTest('valid')" class="btn-mono text-xs">
                ⚡ Run Valid Self-Test
            </button>
            <button onclick="runCryptoTest('attack')" class="btn-mono text-xs text-red-500">
                🛡️ Test Policy Block
            </button>
            <button id="theme-toggle-btn" onclick="toggleTheme()" class="btn-mono text-xs">
                ☀️ Light
            </button>
        </div>
    </header>

    <!-- Navigation Tabs -->
    <nav class="border-b-subtle bg-surface px-6 flex space-x-2">
        <button id="btn-tab-status" onclick="switchTab('status')" class="tab-btn active">
            Gateway Status & Active Connections
        </button>
        <button id="btn-tab-incidents" onclick="switchTab('incidents')" class="tab-btn">
            Break-Glass Incidents <span id="badge-incidents" class="hidden px-1.5 py-0.2 rounded-full text-[10px] bg-red-500 text-white font-bold ml-1">0</span>
        </button>
        <button id="btn-tab-firewall" onclick="switchTab('firewall')" class="tab-btn">
            Live MCP Firewall Feed
        </button>
        <button id="btn-tab-inspector" onclick="switchTab('inspector')" class="tab-btn">
            Token Studio & Inspector
        </button>
    </nav>

    <!-- Main Workspace -->
    <main class="p-6 max-w-6xl mx-auto w-full flex-1 space-y-6">
        <!-- TAB 1: GATEWAY STATUS & ACTIVE CONNECTIONS -->
        <section id="tab-status" class="tab-content space-y-4">
            <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div class="p-4 rounded border-subtle bg-surface space-y-1">
                    <span class="text-[11px] text-dim mono">GATEWAY STATUS</span>
                    <div class="text-sm font-bold text-emerald-500 mono flex items-center gap-1.5">
                        <span class="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                        ONLINE (PORT 8080)
                    </div>
                    <p class="text-[11px] text-sub mono" id="stat-endpoint">http://127.0.0.1:8080/mcp</p>
                </div>

                <div class="p-4 rounded border-subtle bg-surface space-y-1">
                    <span class="text-[11px] text-dim mono">ACTIVE CLIENTS</span>
                    <div class="text-sm font-bold text-main mono" id="stat-sessions">0 connected</div>
                    <p class="text-[11px] text-sub mono">Live MCP Sessions</p>
                </div>

                <div class="p-4 rounded border-subtle bg-surface space-y-1">
                    <span class="text-[11px] text-dim mono">HARDWARE</span>
                    <div class="text-sm font-bold text-main mono" id="stat-cpu">Apple Silicon (M3 Pro)</div>
                    <p class="text-[11px] text-sub mono">ARM64 Neon Native</p>
                </div>

                <div class="p-4 rounded border-subtle bg-surface space-y-1">
                    <span class="text-[11px] text-dim mono">REVOCATIONS</span>
                    <div class="text-sm font-bold text-main mono" id="stat-revocations">0 in memory</div>
                    <p class="text-[11px] text-sub mono">Sub-microsecond</p>
                </div>
            </div>

            <!-- Live Connected Clients Table -->
            <div class="rounded border-subtle bg-surface overflow-hidden space-y-2 p-4">
                <div class="flex items-center justify-between">
                    <h3 class="text-xs font-bold text-main uppercase tracking-wider">Live Connected MCP Client Sessions</h3>
                    <span class="badge-outline mono text-[11px]">Real-Time Active Tracking</span>
                </div>
                <div class="overflow-x-auto">
                    <table class="table-mono w-full">
                        <thead>
                            <tr>
                                <th>Client Identity</th>
                                <th>Protocol</th>
                                <th>Last Active</th>
                                <th>Calls</th>
                                <th>Last Tool</th>
                                <th>Session</th>
                                <th>Security Posture</th>
                            </tr>
                        </thead>
                        <tbody id="sessions-tbody"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB 2: BREAK-GLASS INCIDENTS (HITL) -->
        <section id="tab-incidents" class="tab-content hidden space-y-4">
            <div class="flex items-center justify-between">
                <div>
                    <h2 class="text-sm font-bold uppercase tracking-wider text-main">Break-Glass Security Incidents & HITL Review</h2>
                    <p class="text-xs text-sub">Human-in-the-Loop decision gateway for blocked policy violations and quarantine actions.</p>
                </div>
                <span class="badge-outline mono text-red-500">Slack / PagerDuty Dispatch Active</span>
            </div>

            <div class="rounded border-subtle bg-surface overflow-x-auto">
                <table class="table-mono w-full">
                    <thead>
                        <tr>
                            <th>Incident ID</th>
                            <th>Time</th>
                            <th>Caller Agent</th>
                            <th>Tool Requested</th>
                            <th>Violation Details</th>
                            <th>Review Status</th>
                            <th>HITL Actions</th>
                        </tr>
                    </thead>
                    <tbody id="incidents-tbody"></tbody>
                </table>
            </div>
        </section>

        <!-- TAB 3: FIREWALL STREAM -->
        <section id="tab-firewall" class="tab-content hidden space-y-4">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div class="flex items-center space-x-2">
                    <input id="search-tool" oninput="renderFirewallFeed()" type="text" placeholder="Filter by caller or tool..." class="px-3 py-1.5 rounded border-subtle bg-surface text-xs text-main focus:outline-none w-64">
                    <select id="filter-status" onchange="renderFirewallFeed()" class="px-2.5 py-1.5 rounded border-subtle bg-surface text-xs text-main focus:outline-none">
                        <option value="all">All Events</option>
                        <option value="allowed">Allowed Only</option>
                        <option value="blocked">Blocked Only</option>
                    </select>
                </div>
                <button onclick="exportLogsNDJSON()" class="btn-mono flex items-center gap-1.5">
                    ⬇ Export NDJSON Logs
                </button>
            </div>

            <div class="rounded border-subtle bg-surface overflow-x-auto">
                <table class="table-mono w-full">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Caller Identity</th>
                            <th>Tool Requested</th>
                            <th>Decision</th>
                            <th>Latency / Details</th>
                        </tr>
                    </thead>
                    <tbody id="firewall-tbody"></tbody>
                </table>
            </div>
        </section>

        <!-- TAB 4: TOKEN INSPECTOR -->
        <section id="tab-inspector" class="tab-content hidden space-y-4">
            <div>
                <h2 class="text-sm font-bold uppercase tracking-wider text-main">Post-Quantum Token Inspector</h2>
                <p class="text-xs text-sub">Inspect binary lattice signatures and decode root caveats.</p>
            </div>

            <div class="p-5 rounded border-subtle bg-surface space-y-3">
                <div class="flex justify-between items-center">
                    <label class="text-xs font-bold text-main">Hex Capability Token</label>
                    <button onclick="loadSampleToken()" class="text-xs text-sub hover:text-main underline cursor-pointer">Load Sample Token</button>
                </div>
                <textarea id="inspect-input" rows="3" placeholder="Paste hex token string..." class="w-full p-3 rounded border-subtle bg-app text-xs mono text-main focus:outline-none resize-none"></textarea>
                <button onclick="inspectToken()" class="btn-mono-primary">
                    Decode & Verify Token
                </button>
                <div id="inspect-result" class="hidden"></div>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="border-t-subtle bg-surface px-6 py-3 text-center text-[11px] text-dim mono">
        PeithoSecure Gateway Core • NIST FIPS 203 & 204
    </footer>

    <script>{js}</script>
</body>
</html>"#)
}
