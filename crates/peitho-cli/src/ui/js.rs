//! Minimalist client-side JavaScript for theme toggle, tabs, and real-time backend communication.

/// Return the complete client-side JavaScript logic.
pub fn get_javascript() -> &'static str {
    r#"
let currentTheme = localStorage.getItem('peitho-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
document.documentElement.setAttribute('data-theme', currentTheme);
updateThemeIcon();

function toggleTheme() {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('peitho-theme', currentTheme);
    updateThemeIcon();
}

function updateThemeIcon() {
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) btn.innerHTML = currentTheme === 'dark' ? '☀️ <span class="hidden sm:inline">Light</span>' : '🌙 <span class="hidden sm:inline">Dark</span>';
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(el => {
        el.classList.remove('border-b-2', 'border-black', 'dark:border-white', 'text-main', 'font-semibold');
        el.classList.add('text-sub');
    });
    const target = document.getElementById('tab-' + tabId);
    const btn = document.getElementById('btn-tab-' + tabId);
    if (target) target.classList.remove('hidden');
    if (btn) {
        btn.classList.add('border-b-2', 'border-black', 'dark:border-white', 'text-main', 'font-semibold');
        btn.classList.remove('text-sub');
    }
}

async function fetchTelemetry() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        const host = document.getElementById('stat-cpu');
        const rev = document.getElementById('stat-revocations');
        const end = document.getElementById('stat-endpoint');
        const sess = document.getElementById('stat-sessions');
        const badge = document.getElementById('badge-incidents');
        if (host && data.host_cpu) host.textContent = data.host_cpu;
        if (rev) rev.textContent = data.revocations_count + ' in memory';
        if (end && data.listening_on) end.textContent = data.listening_on;
        if (sess) sess.textContent = (data.active_sessions_count || 0) + ' connected';
        if (badge) {
            if (data.pending_incidents_count > 0) {
                badge.textContent = data.pending_incidents_count;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        }
    } catch(e) {}
}
setInterval(fetchTelemetry, 2000);
fetchTelemetry();

let eventsLog = [];

async function fetchEvents() {
    try {
        const res = await fetch('/api/events');
        eventsLog = await res.json();
        renderFirewallFeed();
    } catch(e) {}
}
setInterval(fetchEvents, 2000);
fetchEvents();

async function fetchSessions() {
    try {
        const res = await fetch('/api/sessions');
        const list = await res.json();
        renderSessionsTable(list);
    } catch(e) {}
}
setInterval(fetchSessions, 2000);
fetchSessions();

async function fetchIncidents() {
    try {
        const res = await fetch('/api/incidents');
        const list = await res.json();
        renderIncidentsTable(list);
    } catch(e) {}
}
setInterval(fetchIncidents, 2000);
fetchIncidents();

function renderSessionsTable(sessions) {
    const container = document.getElementById('sessions-tbody');
    if (!container) return;
    if (!sessions || sessions.length === 0) {
        container.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-xs text-sub mono">No active MCP client sessions yet.</td></tr>`;
        return;
    }
    container.innerHTML = sessions.map(s => {
        let secBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">🟢 HEALTHY</span>`;
        if (s.security_status === 'ATTACK BLOCKED') secBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20 font-bold">🔴 ATTACK BLOCKED</span>`;
        if (s.security_status === 'AUTH FAILURE') secBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20 font-bold">🔴 AUTH FAILURE</span>`;
        if (s.security_status === 'QUARANTINED') secBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">🚫 QUARANTINED</span>`;

        return `
            <tr class="border-b border-subtle text-xs hover:bg-surface-hover">
                <td class="p-3 font-semibold text-main mono">${s.caller}</td>
                <td class="p-3 mono text-sub">${s.protocol}</td>
                <td class="p-3 mono text-dim">${s.last_active}</td>
                <td class="p-3 mono text-main">${s.requests_count}</td>
                <td class="p-3 mono text-sub">${s.last_tool}</td>
                <td class="p-3"><span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">● ${s.session_status}</span></td>
                <td class="p-3">${secBadge}</td>
            </tr>
        `;
    }).join('');
}

function renderIncidentsTable(incidents) {
    const container = document.getElementById('incidents-tbody');
    if (!container) return;
    if (!incidents || incidents.length === 0) {
        container.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-xs text-sub mono">No security violations recorded. All agent calls compliant.</td></tr>`;
        return;
    }
    container.innerHTML = incidents.map(i => {
        let statusBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border border-yellow-500/20">PENDING REVIEW</span>`;
        if (i.status === 'ApprovedOnce') statusBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">APPROVED ONCE</span>`;
        if (i.status === 'Quarantined') statusBadge = `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-red-500/10 text-red-600 border border-red-500/20">QUARANTINED</span>`;

        let actions = `<span class="text-dim text-[11px] mono">Action Completed</span>`;
        if (i.status === 'PendingReview') {
            actions = `
                <div class="flex items-center gap-1.5">
                    <button onclick="approveIncident('${i.incident_id}')" class="btn-mono text-[10px] py-0.5 px-2 bg-emerald-500/10 text-emerald-600 border-emerald-500/30">Authorize Once</button>
                    <button onclick="quarantineIncident('${i.incident_id}')" class="btn-mono text-[10px] py-0.5 px-2 bg-red-500/10 text-red-600 border-red-500/30">Quarantine</button>
                </div>
            `;
        }

        return `
            <tr class="border-b border-subtle text-xs hover:bg-surface-hover">
                <td class="p-3 mono font-semibold text-main">${i.incident_id}</td>
                <td class="p-3 mono text-dim">${i.timestamp}</td>
                <td class="p-3 font-medium text-main">${i.caller_identity}</td>
                <td class="p-3 mono text-sub">${i.tool_requested}</td>
                <td class="p-3 text-red-500 text-[11px]">${i.violation_reason}</td>
                <td class="p-3">${statusBadge}</td>
                <td class="p-3">${actions}</td>
            </tr>
        `;
    }).join('');
}

async function approveIncident(id) {
    await fetch('/api/incidents/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ incident_id: id }) });
    fetchIncidents(); fetchSessions(); fetchTelemetry();
}

async function quarantineIncident(id) {
    await fetch('/api/incidents/quarantine', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ incident_id: id }) });
    fetchIncidents(); fetchSessions(); fetchTelemetry();
}

async function runCryptoTest(scenario) {
    try {
        const res = await fetch('/api/test-crypto?scenario=' + scenario, { method: 'POST' });
        const evt = await res.json();
        eventsLog.unshift(evt);
        renderFirewallFeed(); fetchTelemetry(); fetchSessions(); fetchIncidents(); switchTab('firewall');
    } catch(e) {}
}

function renderFirewallFeed() {
    const container = document.getElementById('firewall-tbody');
    if (!container) return;
    const filter = document.getElementById('filter-status')?.value || 'all';
    const search = (document.getElementById('search-tool')?.value || '').toLowerCase();

    if (eventsLog.length === 0) {
        container.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-xs text-sub mono">No incoming MCP requests yet. Listening on <span class="text-main font-semibold">http://127.0.0.1:8080/mcp</span>.</td></tr>`;
        return;
    }

    const filtered = eventsLog.filter(e => {
        if (filter === 'allowed' && !e.allowed) return false;
        if (filter === 'blocked' && e.allowed) return false;
        if (search && !e.tool.toLowerCase().includes(search) && !e.caller.toLowerCase().includes(search)) return false;
        return true;
    });

    container.innerHTML = filtered.map(e => `
        <tr class="border-b border-subtle text-xs hover:bg-surface-hover">
            <td class="p-3 mono text-dim">${e.time}</td>
            <td class="p-3 font-medium text-main">${e.caller}</td>
            <td class="p-3 mono text-sub">${e.tool}</td>
            <td class="p-3"><span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium ${e.allowed ? 'bg-emerald-500/10 text-emerald-600 border border-emerald-500/20' : 'bg-red-500/10 text-red-600 border border-red-500/20'}">${e.allowed ? '● ALLOWED' : '■ BLOCKED'}</span></td>
            <td class="p-3 mono text-sub">${e.allowed ? (e.latency_micros + ' µs (' + e.reason + ')') : e.reason}</td>
        </tr>
    `).join('');
}

async function inspectToken() {
    const hex = document.getElementById('inspect-input').value.trim();
    const out = document.getElementById('inspect-result');
    if (!hex || !out) return;
    try {
        const res = await fetch('/api/inspect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token_hex: hex }) });
        const data = await res.json();
        out.classList.remove('hidden');
        if (data.valid) {
            out.className = 'p-4 rounded border border-emerald-500/30 bg-emerald-500/5 text-xs mono text-main space-y-1.5';
            out.innerHTML = `<div class="font-bold text-emerald-600 dark:text-emerald-400">✓ Cryptographically Valid Post-Quantum Token</div><div>Token ID: <span class="font-semibold">${data.token_id}</span></div><div>Crypto Profile: <span class="font-semibold">${data.profile}</span></div><div>Delegation Depth: <span class="font-semibold">${data.delegation_depth} hop(s)</span></div><div>Root Caveats: <span class="font-semibold">${data.root_caveats_count} predicate(s)</span></div>`;
        } else {
            out.className = 'p-4 rounded border border-red-500/30 bg-red-500/5 text-xs mono text-red-600 dark:text-red-400';
            out.innerHTML = `<div>✗ Invalid Token: ${data.error}</div>`;
        }
    } catch(e) { out.textContent = 'Error: ' + e; }
}

async function loadSampleToken() {
    try {
        const res = await fetch('/api/sample-token');
        const data = await res.json();
        const el = document.getElementById('inspect-input');
        if (el) { el.value = data.token_hex; inspectToken(); }
    } catch(e) {}
}

function exportLogsNDJSON() {
    const blob = new Blob([eventsLog.map(e => JSON.stringify(e)).join('\n')], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'peitho_audit_' + Date.now() + '.ndjson';
    a.click();
}
"#
}
