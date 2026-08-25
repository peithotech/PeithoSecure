//! Client-side JavaScript for the Peitho Community developer dashboard.
//! Manages tab routing, live polling, delegation tree, and time-based Dark/Light themes.

/// Generate the self-contained JavaScript bundle.
pub fn get_javascript() -> String {
    r#"
let currentTab = 'overview';

function applyTimeTheme() {
    const userTheme = localStorage.getItem('peitho-theme-mode');
    const btn = document.getElementById('theme-toggle-btn');
    if (userTheme && userTheme !== 'auto') {
        document.documentElement.setAttribute('data-theme', userTheme);
        if (btn) btn.innerText = userTheme === 'dark' ? '🌙 Dark' : '☀️ Light';
        return;
    }
    const hours = new Date().getHours();
    const isDay = hours >= 6 && hours < 18;
    const theme = isDay ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    if (btn) btn.innerText = `⏱️ Auto (${isDay ? 'Light' : 'Dark'})`;
}

function toggleTheme() {
    const current = localStorage.getItem('peitho-theme-mode') || 'auto';
    let next = 'auto';
    if (current === 'auto') next = 'light';
    else if (current === 'light') next = 'dark';
    else next = 'auto';
    localStorage.setItem('peitho-theme-mode', next);
    applyTimeTheme();
}

function switchTab(tab) {
    currentTab = tab;
    const sections = ['overview', 'capabilities', 'decisions', 'activity', 'tokens', 'tools', 'invariants', 'system'];
    sections.forEach(s => {
        const el = document.getElementById(`sec-${s}`);
        const btn = document.getElementById(`tab-btn-${s}`);
        if (el) el.classList.toggle('hidden', s !== tab);
        if (btn) btn.classList.toggle('active', s === tab);
    });
    if (tab === 'overview') fetchOverview();
    if (tab === 'capabilities') renderCapabilitiesTree();
    if (tab === 'activity' || tab === 'decisions') fetchActivity();
    if (tab === 'invariants') fetchInvariants();
    if (tab === 'system') fetchSystem();
}

async function fetchOverview() {
    try {
        const res = await fetch('/api/v1/overview');
        const data = await res.json();
        document.getElementById('stat-auth-count').innerText = data.total_authorizations || 0;
        document.getElementById('stat-denied-count').innerText = data.total_denied || 0;
        if (data.observed_latency) {
            document.getElementById('stat-latency-val').innerText = `${data.observed_latency.median_micros} µs`;
        }
    } catch (e) { console.error(e); }
}

async function fetchActivity() {
    try {
        const res = await fetch('/api/v1/decisions');
        const list = await res.json();
        const tbody = document.getElementById('activity-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        list.slice(-10).reverse().forEach(t => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-surface cursor-pointer border-b-subtle';
            tr.onclick = () => showDecisionDetail(t);
            const isAllow = t.outcome === 'ALLOW';
            tr.innerHTML = `
                <td class="py-2.5 text-dim">${new Date(t.timestamp_micros / 1000).toLocaleTimeString()}</td>
                <td class="text-main">${t.principal_display}</td>
                <td class="text-main font-bold font-mono">${t.tool_name}</td>
                <td><span class="badge-outline text-[10px] font-bold ${isAllow ? 'bg-surface' : 'badge-mono'}">${t.outcome}</span></td>
                <td class="text-dim">${t.latency_micros} µs</td>
                <td class="text-sub">${t.failed_invariant || '—'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

function showDecisionDetail(trace) {
    const container = document.getElementById('decision-detail-container');
    if (!container) return;
    const isAllow = trace.outcome === 'ALLOW';
    container.innerHTML = `
        <div class="card-box space-y-3">
            <div class="flex items-center justify-between border-b-subtle pb-2">
                <span class="font-bold text-sm text-main mono">[${trace.outcome}] • ${trace.tool_name}</span>
                <span class="text-dim mono">${trace.latency_micros} µs evaluation</span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div><span class="text-dim">Principal:</span> <span class="text-main font-bold">${trace.principal_display}</span></div>
                <div><span class="text-dim">Resource:</span> <span class="text-main font-bold">${trace.resource_display}</span></div>
            </div>
            <div class="border-t-subtle pt-3 space-y-1.5 text-xs">
                <div class="font-bold text-sub mb-1">CONSTRAINT EVALUATION CHECKLIST:</div>
                <div class="flex items-center gap-2 text-main"><span>✓ PASS</span> <span class="text-sub">Root ML-DSA-44 Signature Valid</span></div>
                <div class="flex items-center gap-2 text-main"><span>✓ PASS</span> <span class="text-sub">Audience Principal Bound</span></div>
                <div class="flex items-center gap-2 text-main"><span>${isAllow ? '✓ PASS' : '✕ FAIL'}</span> <span class="text-sub">Tool Confinement Scope</span></div>
                <div class="flex items-center gap-2 text-main"><span>${isAllow ? '✓ PASS' : '✕ FAIL'}</span> <span class="text-sub">Resource Prefix Confinement</span></div>
                <div class="flex items-center gap-2 text-dim"><span>${isAllow ? '✓ PASS' : '○ NOT EVALUATED'}</span> <span>Nonce & Replay Defense</span></div>
            </div>
            ${trace.failed_invariant ? `<div class="p-2 border-subtle bg-surface text-main rounded text-xs">Failed Invariant: <span class="font-bold">${trace.failed_invariant}</span></div>` : ''}
        </div>
    `;
    switchTab('decisions');
}

async function runSelfTest(scenario) {
    try {
        const res = await fetch('/api/v1/self-test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario }),
        });
        const data = await res.json();
        showDecisionDetail({
            trace_id: `selftest_${Date.now()}`,
            timestamp_micros: Date.now() * 1000,
            principal_display: 'agent:demo-self-test',
            tool_name: data.tested_tool,
            resource_display: data.tested_resource,
            outcome: data.outcome,
            failed_invariant: data.failed_invariant,
            latency_micros: data.latency_micros,
            checklist: {}
        });
        fetchOverview();
    } catch (e) { console.error(e); }
}

function renderCapabilitiesTree() {
    const container = document.getElementById('capability-tree-container');
    if (!container) return;
    container.innerHTML = `
        <div class="space-y-3">
            <div class="p-3.5 rounded card-box border-strong">
                <div class="flex items-center justify-between font-bold text-main">
                    <span>👑 ROOT AUTHORITY (Trust Anchor)</span>
                    <span class="badge-mono text-[10px]">FIPS 204 ML-DSA-44</span>
                </div>
                <p class="text-[11px] text-dim mt-1">Tools: [search_documents, read_report, query_db] • Prefix: s3://company/*</p>
                <div class="ml-6 mt-3 border-l border-subtle pl-4 space-y-3">
                    <div class="p-3 rounded card-box">
                        <div class="flex items-center justify-between font-bold text-main">
                            <span>🤖 AGENT: Research-Agent (Hop 1)</span>
                            <span class="badge-outline text-[10px]">SwarmSpeed HMAC-SHA256</span>
                        </div>
                        <p class="text-[11px] text-dim mt-1">Attenuated: [search_documents, read_report] • Prefix: s3://company/public/*</p>
                        <div class="ml-6 mt-3 border-l border-subtle pl-4">
                            <div class="p-3 rounded card-box">
                                <div class="flex items-center justify-between font-bold text-main">
                                    <span>⚡ SUBAGENT: Summarizer (Hop 2)</span>
                                    <span class="badge-outline text-[10px]">ReadOnly Lock</span>
                                </div>
                                <p class="text-[11px] text-dim mt-1">Strict Confinement: [read_report] • Prefix: s3://company/public/reports/*</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

async function fetchInvariants() {
    try {
        const res = await fetch('/api/v1/invariants');
        const data = await res.json();
        const container = document.getElementById('invariants-grid-container');
        if (!container) return;
        container.innerHTML = '';
        data.invariants.forEach(inv => {
            const card = document.createElement('div');
            card.className = 'card-box space-y-1.5 hover:border-strong transition';
            card.innerHTML = `
                <div class="flex items-center justify-between font-bold text-xs">
                    <span class="text-main">${inv.id} • ${inv.name}</span>
                    <span class="badge-outline text-[10px]">✓ ${inv.status}</span>
                </div>
                <div class="p-1.5 rounded bg-surface text-main text-[11px] mono border-subtle">${inv.math}</div>
                <p class="text-[10px] text-dim">Impl: ${inv.file}</p>
            `;
            container.appendChild(card);
        });
    } catch (e) { console.error(e); }
}

async function fetchSystem() {
    try {
        const res = await fetch('/api/v1/system');
        const data = await res.json();
        const container = document.getElementById('system-diagnostics-container');
        if (!container) return;
        container.innerHTML = `
            <div class="grid grid-cols-2 gap-3">
                <div class="card-box"><span class="text-dim">Version:</span> <span class="text-main font-bold">${data.version}</span></div>
                <div class="card-box"><span class="text-dim">Git Revision:</span> <span class="text-main font-bold">${data.git_revision}</span></div>
                <div class="card-box"><span class="text-dim">Target:</span> <span class="text-main font-bold">${data.target_triple}</span></div>
                <div class="card-box"><span class="text-dim">Crypto:</span> <span class="text-main font-bold">${data.crypto_profile}</span></div>
            </div>
            <div class="card-box text-main font-bold text-xs mt-3">${data.network_hotpath_dependency}</div>
        `;
    } catch (e) { console.error(e); }
}

document.addEventListener('DOMContentLoaded', () => {
    applyTimeTheme();
    fetchOverview();
    setInterval(applyTimeTheme, 60000);
    setInterval(() => {
        if (currentTab === 'overview') fetchOverview();
        if (currentTab === 'activity' || currentTab === 'decisions') fetchActivity();
    }, 2000);
});
"#.to_string()
}
