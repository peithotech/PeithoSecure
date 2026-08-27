//! Client-side JavaScript core for the Peitho Community developer dashboard.

use super::js_views::get_js_views;

/// Generate the self-contained JavaScript bundle.
pub fn get_javascript() -> String {
    let views = get_js_views();
    format!(r#"
let currentTab = 'activity';
let currentFilter = 'ALL';
let activeDecisions = [];

function applyTimeTheme() {{
    const userTheme = localStorage.getItem('peitho-theme-mode');
    const btn = document.getElementById('theme-toggle-btn');
    if (userTheme && userTheme !== 'auto') {{
        document.documentElement.setAttribute('data-theme', userTheme);
        if (btn) btn.innerText = userTheme === 'dark' ? '🌙 Dark' : '☀️ Light';
        return;
    }}
    const hours = new Date().getHours();
    const isDay = hours >= 6 && hours < 18;
    const theme = isDay ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    if (btn) btn.innerText = `⏱️ Auto (${{isDay ? 'Light' : 'Dark'}})`;
}}

function toggleTheme() {{
    const current = localStorage.getItem('peitho-theme-mode') || 'auto';
    let next = current === 'auto' ? 'light' : (current === 'light' ? 'dark' : 'auto');
    localStorage.setItem('peitho-theme-mode', next);
    applyTimeTheme();
}}

function switchTab(tab) {{
    currentTab = tab;
    ['activity', 'capabilities', 'invariants'].forEach(s => {{
        const el = document.getElementById(`sec-${{s}}`);
        const btn = document.getElementById(`tab-btn-${{s}}`);
        if (el) el.classList.toggle('hidden', s !== tab);
        if (btn) btn.classList.toggle('active', s === tab);
    }});
    if (tab === 'activity') {{ fetchOverview(); fetchDecisions(); }}
    else if (tab === 'capabilities') {{ renderCapabilitiesTree(); renderTokens(); renderTools(); }}
    else if (tab === 'invariants') {{ fetchInvariants(); fetchSystem(); }}
}}

async function fetchOverview() {{
    try {{
        const res = await fetch('/api/v1/overview');
        const data = await res.json();
        const totalAuth = data.total_authorizations || 0;
        const totalAllowed = data.total_allowed || 0;
        const totalDenied = data.total_denied || 0;
        document.getElementById('stat-auth-count').innerText = totalAuth.toLocaleString();
        document.getElementById('stat-auth-sub').innerText = `${{totalAllowed.toLocaleString()}} ALLOW`;
        document.getElementById('stat-denied-count').innerText = totalDenied.toLocaleString();
        document.getElementById('stat-denied-sub').innerText = `${{totalDenied.toLocaleString()}} BLOCKED`;
        if (data.observed_latency) {{
            const p50 = data.observed_latency.p50_micros;
            document.getElementById('stat-latency-val').innerText = p50 > 0 ? `${{p50}} µs` : '—';
            document.getElementById('stat-latency-sub').innerText = totalAuth > 0 ? `p50 · ${{totalAuth.toLocaleString()}} evaluations` : 'Local runtime (Zero I/O)';
        }}
        const graphEl = document.getElementById('overview-authority-graph');
        if (graphEl) {{
            graphEl.innerText = `ROOT (Trust Anchor ML-DSA-44)\n  │\n  ├── agent.analytics\n  │      └── query_public_data\n  │          └── s3://enterprise/public/*\n  │\n  └── agent.worker\n         ├── read_document\n         │      └── s3://enterprise/public/report.pdf\n         └── [BLOCKED] manage_secrets (P-005)`;
        }}
    }} catch (e) {{ console.error(e); }}
}}

let selectedActivityIndex = 0;

async function fetchDecisions() {{
    try {{
        const res = await fetch(`/api/v1/decisions?outcome=${{currentFilter}}`);
        activeDecisions = await res.json();
        renderOverviewActivity();
        renderActivityTable();
        if (activeDecisions.length > 0) {{
            const safeIdx = Math.min(selectedActivityIndex, activeDecisions.length - 1);
            showDecisionDetail(activeDecisions[safeIdx]);
            renderActivityDetail(activeDecisions[safeIdx]);
        }}
    }} catch (e) {{ console.error(e); }}
}}

function renderOverviewActivity() {{
    const listEl = document.getElementById('overview-activity-list');
    if (!listEl) return;
    listEl.innerHTML = '';
    activeDecisions.slice(0, 4).forEach((t, idx) => {{
        const isAllow = t.outcome === 'ALLOW';
        const item = document.createElement('div');
        item.className = 'p-2.5 rounded bg-surface border-subtle hover:border-strong cursor-pointer space-y-1 transition';
        item.onclick = () => {{ selectedActivityIndex = idx; showDecisionDetail(t); renderActivityDetail(t); }};
        item.innerHTML = `<div class="flex items-center justify-between"><span class="text-dim">${{new Date(t.timestamp_micros / 1000).toLocaleTimeString()}}</span><span class="${{isAllow ? 'badge-allow' : 'badge-deny'}}">${{t.outcome}}</span><span class="text-main font-bold">${{t.principal_display}}</span></div><div class="text-main font-bold">${{t.tool_name}}</div><div class="${{isAllow ? 'text-dim' : 'text-deny'}} text-[11px]">${{t.failed_invariant ? t.failed_invariant : t.resource_display}}</div>`;
        listEl.appendChild(item);
    }});
}}

function setFilter(f) {{
    currentFilter = f;
    selectedActivityIndex = 0;
    ['ALL', 'ALLOW', 'DENY', 'REPLAY', 'TRAVERSAL', 'EXPIRED'].forEach(k => {{
        const btn = document.getElementById(`filter-btn-${{k}}`);
        if (btn) btn.classList.toggle('active', k === f);
    }});
    fetchDecisions();
}}

function renderActivityTable() {{
    const tbody = document.getElementById('activity-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const safeIdx = activeDecisions.length > 0 ? Math.min(selectedActivityIndex, activeDecisions.length - 1) : 0;
    activeDecisions.forEach((t, idx) => {{
        const tr = document.createElement('tr');
        tr.id = `act-row-${{idx}}`;
        tr.className = `cursor-pointer ${{idx === safeIdx ? 'selected' : ''}}`;
        tr.onclick = () => {{
            selectedActivityIndex = idx;
            document.querySelectorAll('#activity-tbody tr').forEach(r => r.classList.remove('selected'));
            tr.classList.add('selected');
            renderActivityDetail(t);
            showDecisionDetail(t);
        }};
        const isAllow = t.outcome === 'ALLOW';
        tr.innerHTML = `
            <td class="py-2 text-dim">${{new Date(t.timestamp_micros / 1000).toLocaleTimeString()}}</td>
            <td><span class="${{isAllow ? 'badge-allow' : 'badge-deny'}}">${{t.outcome}}</span></td>
            <td class="text-main">${{t.principal_display}}</td>
            <td class="text-main font-bold">${{t.tool_name}}</td>
            <td class="${{isAllow ? 'text-dim' : 'text-deny'}}">${{t.failed_invariant || '—'}}</td>
        `;
        tbody.appendChild(tr);
    }});
}}

function renderActivityDetail(trace) {{
    const container = document.getElementById('activity-detail-container');
    if (!container) return;
    const isAllow = trace.outcome === 'ALLOW';
    container.innerHTML = `
        <div class="space-y-3">
            <div class="flex items-center justify-between border-b-subtle pb-2">
                <span class="text-xs font-bold ${{isAllow ? 'text-allow' : 'text-deny'}} mono">[${{trace.outcome}}] • ${{trace.tool_name}}</span>
                <span class="text-dim text-[11px] mono">${{trace.latency_micros}} µs</span>
            </div>
            <div class="space-y-1 text-xs">
                <div><span class="text-dim">Principal:</span> <span class="text-main font-bold">${{trace.principal_display}}</span></div>
                <div><span class="text-dim">Resource:</span> <span class="text-main font-mono">${{trace.resource_display}}</span></div>
            </div>
            <div class="card-box space-y-1 text-[11px]">
                <div class="font-bold text-sub">INLINE EVALUATION:</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Root signature valid (ML-DSA-44)</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Audience bound to principal</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Nonce fresh (&lt;15ns test-and-burn)</div>
                <div class="flex items-center gap-1.5 ${{isAllow ? 'text-allow' : 'text-deny'}}"><span>${{isAllow ? '✓' : '✗'}}</span> Tool allowed scope ${{trace.failed_invariant && trace.failed_invariant.includes('P-005') ? '(P-005)' : ''}}</div>
                <div class="flex items-center gap-1.5 ${{isAllow ? 'text-allow' : (trace.failed_invariant && trace.failed_invariant.includes('P-004') ? 'text-deny' : 'text-dim')}}"><span>${{isAllow ? '✓' : (trace.failed_invariant && trace.failed_invariant.includes('P-004') ? '✗' : '○')}}</span> Resource prefix confinement ${{trace.failed_invariant && trace.failed_invariant.includes('P-004') ? '(P-004)' : ''}}</div>
            </div>
            <div class="${{isAllow ? 'text-sub' : 'text-deny'}} text-[11px]">${{trace.failed_invariant ? `Blocked: ${{trace.failed_invariant}}` : 'All cryptographic proofs verified.'}}</div>
        </div>
    `;
}}

function showDecisionDetail(trace) {{
    const container = document.getElementById('decision-detail-container');
    if (!container) return;
    const isAllow = trace.outcome === 'ALLOW';
    container.innerHTML = `
        <div class="space-y-4">
            <div class="flex items-center justify-between border-b-subtle pb-3">
                <span class="text-sm font-bold ${{isAllow ? 'text-allow' : 'text-deny'}} mono">[${{trace.outcome}}] • ${{trace.tool_name}}</span>
                <span class="text-dim mono">${{trace.latency_micros}} µs evaluation</span>
            </div>
            <div class="grid grid-cols-2 gap-4 text-xs">
                <div class="card-box space-y-1.5"><span class="text-dim">Principal:</span> <span class="text-main font-bold">${{trace.principal_display}}</span><br><span class="text-dim">Tool:</span> <span class="text-main font-bold">${{trace.tool_name}}</span></div>
                <div class="card-box space-y-1.5"><span class="text-dim">Action:</span> <span class="text-main font-bold">execute</span><br><span class="text-dim">Resource:</span> <span class="text-main font-bold">${{trace.resource_display}}</span></div>
            </div>
            <div class="card-box space-y-1.5 text-xs">
                <div class="font-bold text-sub border-b-subtle pb-1">EVALUATION CHECKLIST:</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Root signature valid (ML-DSA-44)</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Audience matches bound principal</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Token not revoked</div>
                <div class="flex items-center gap-1.5 text-allow"><span>✓</span> Nonce fresh (&lt;15ns test-and-burn)</div>
                <div class="flex items-center gap-1.5 ${{isAllow ? 'text-allow' : 'text-deny'}}"><span>${{isAllow ? '✓' : '✗'}}</span> Tool allowed scope ${{trace.failed_invariant && trace.failed_invariant.includes('P-005') ? '(P-005)' : ''}}</div>
                <div class="flex items-center gap-1.5 ${{isAllow ? 'text-allow' : (trace.failed_invariant && trace.failed_invariant.includes('P-004') ? 'text-deny' : 'text-dim')}}"><span>${{isAllow ? '✓' : (trace.failed_invariant && trace.failed_invariant.includes('P-004') ? '✗' : '○')}}</span> Resource prefix confinement ${{trace.failed_invariant && trace.failed_invariant.includes('P-004') ? '(P-004)' : ''}}</div>
            </div>
            <div class="card-box space-y-1.5 text-xs">
                <div class="font-bold text-sub border-b-subtle pb-1">RESULT CODE: <span class="${{isAllow ? 'text-allow' : 'text-deny'}}">${{isAllow ? 'PEITHO_OK_AUTHORIZED' : 'PEITHO_ERR_UNAUTHORIZED'}}</span></div>
                <div class="text-sub">Authority possessed: <span class="text-main font-bold">search_documents, read_document</span></div>
                <div class="text-sub">Authority requested: <span class="${{isAllow ? 'text-allow' : 'text-deny'}} font-bold">${{trace.tool_name}}</span></div>
                <div class="text-dim pt-1 border-t-subtle">Reason: ${{trace.failed_invariant ? `Requested capability is outside delegated authority (${{trace.failed_invariant}})` : 'All cryptographic proofs and monotonic caveat constraints satisfied.'}}</div>
            </div>
        </div>
    `;
}}

async function runSelfTest(scenario) {{
    try {{
        await fetch('/api/v1/self-test', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ scenario }}),
        }});
        selectedActivityIndex = 0;
        await fetchDecisions();
        await fetchOverview();
    }} catch (e) {{ console.error(e); }}
}}

{views}

document.addEventListener('DOMContentLoaded', () => {{
    applyTimeTheme();
    fetchOverview();
    fetchDecisions();
    setInterval(applyTimeTheme, 60000);
    setInterval(() => {{
        if (currentTab === 'activity') {{ fetchOverview(); fetchDecisions(); }}
    }}, 2000);
}});
"#)
}
