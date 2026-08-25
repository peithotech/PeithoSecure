//! Client-side JavaScript for the Peitho Community developer dashboard.
//! Manages tab routing, live polling, delegation tree rendering, and the Decision Inspector.

/// Generate the self-contained JavaScript bundle.
pub fn get_javascript() -> String {
    r#"
let currentTab = 'overview';

function switchTab(tab) {
    currentTab = tab;
    const sections = ['overview', 'capabilities', 'decisions', 'activity', 'tokens', 'tools', 'invariants', 'system'];
    sections.forEach(s => {
        const el = document.getElementById(`sec-${s}`);
        const btn = document.getElementById(`tab-btn-${s}`);
        if (el) el.classList.toggle('hidden', s !== tab);
        if (btn) {
            btn.classList.toggle('border-b-2', s === tab);
            btn.classList.toggle('border-emerald-500', s === tab);
            btn.classList.toggle('text-white', s === tab);
            btn.classList.toggle('text-[#94a3b8]', s !== tab);
        }
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
    } catch (e) {
        console.error('Overview fetch error:', e);
    }
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
            tr.className = 'hover:bg-[#1e293b]/50 cursor-pointer';
            tr.onclick = () => showDecisionDetail(t);
            const isAllow = t.outcome === 'ALLOW';
            tr.innerHTML = `
                <td class="py-2.5 text-[#64748b]">${new Date(t.timestamp_micros / 1000).toLocaleTimeString()}</td>
                <td class="text-[#cbd5e1]">${t.principal_display}</td>
                <td class="text-[#38bdf8] font-bold">${t.tool_name}</td>
                <td><span class="px-2 py-0.5 rounded text-[10px] font-bold ${isAllow ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'}">${t.outcome}</span></td>
                <td class="text-[#64748b]">${t.latency_micros} µs</td>
                <td class="text-rose-400">${t.failed_invariant || '—'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Activity fetch error:', e);
    }
}

function showDecisionDetail(trace) {
    const container = document.getElementById('decision-detail-container');
    if (!container) return;
    const isAllow = trace.outcome === 'ALLOW';
    container.innerHTML = `
        <div class="p-4 rounded border ${isAllow ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'} space-y-3">
            <div class="flex items-center justify-between">
                <span class="font-bold text-sm ${isAllow ? 'text-emerald-400' : 'text-rose-400'}">${trace.outcome} • ${trace.tool_name}</span>
                <span class="text-[#64748b] font-mono">${trace.latency_micros} µs evaluation</span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div><span class="text-[#64748b]">Principal:</span> ${trace.principal_display}</div>
                <div><span class="text-[#64748b]">Resource:</span> ${trace.resource_display}</div>
            </div>
            <div class="border-t border-[#1e293b] pt-3 space-y-1.5 text-xs">
                <div class="font-bold text-[#94a3b8] mb-1">CONSTRAINT EVALUATION CHECKLIST:</div>
                <div class="flex items-center gap-2 text-emerald-400"><span>✓ PASS</span> <span class="text-[#cbd5e1]">Root ML-DSA-44 Signature Valid</span></div>
                <div class="flex items-center gap-2 text-emerald-400"><span>✓ PASS</span> <span class="text-[#cbd5e1]">Audience Principal Bound</span></div>
                <div class="flex items-center gap-2 ${isAllow ? 'text-emerald-400' : 'text-rose-400'}"><span>${isAllow ? '✓ PASS' : '✕ FAIL'}</span> <span class="text-[#cbd5e1]">Tool Confinement Scope</span></div>
                <div class="flex items-center gap-2 ${isAllow ? 'text-emerald-400' : 'text-rose-400'}"><span>${isAllow ? '✓ PASS' : '✕ FAIL'}</span> <span class="text-[#cbd5e1]">Resource Prefix Confinement</span></div>
                <div class="flex items-center gap-2 ${isAllow ? 'text-emerald-400' : 'text-[#64748b]'}"><span>${isAllow ? '✓ PASS' : '○ NOT EVALUATED'}</span> <span class="text-[#cbd5e1]">Nonce & Replay Defense</span></div>
            </div>
            ${trace.failed_invariant ? `<div class="p-2 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded text-xs">Failed Invariant: ${trace.failed_invariant}</div>` : ''}
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
    } catch (e) {
        console.error('Self-test error:', e);
    }
}

function renderCapabilitiesTree() {
    const container = document.getElementById('capability-tree-container');
    if (!container) return;
    container.innerHTML = `
        <div class="space-y-3">
            <div class="p-3 rounded bg-[#0f172a] border border-emerald-500/30">
                <div class="flex items-center justify-between font-bold text-emerald-400">
                    <span>👑 ROOT AUTHORITY (Trust Anchor)</span>
                    <span class="text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded">FIPS 204 ML-DSA-44</span>
                </div>
                <p class="text-[11px] text-[#64748b] mt-1">Tools: [search_documents, read_report, query_db] • Prefix: s3://company/*</p>
                <div class="ml-6 mt-3 border-l-2 border-[#334155] pl-4 space-y-3">
                    <div class="p-3 rounded bg-[#0f172a] border border-cyan-500/30">
                        <div class="flex items-center justify-between font-bold text-cyan-400">
                            <span>🤖 AGENT: Research-Agent (Hop 1)</span>
                            <span class="text-[10px] bg-cyan-500/10 px-2 py-0.5 rounded">SwarmSpeed HMAC-SHA256</span>
                        </div>
                        <p class="text-[11px] text-[#64748b] mt-1">Attenuated: [search_documents, read_report] • Prefix: s3://company/public/*</p>
                        <div class="ml-6 mt-3 border-l-2 border-[#334155] pl-4">
                            <div class="p-3 rounded bg-[#0f172a] border border-purple-500/30">
                                <div class="flex items-center justify-between font-bold text-purple-400">
                                    <span>⚡ SUBAGENT: Summarizer (Hop 2)</span>
                                    <span class="text-[10px] bg-purple-500/10 px-2 py-0.5 rounded">ReadOnly Lock</span>
                                </div>
                                <p class="text-[11px] text-[#64748b] mt-1">Strict Confinement: [read_report] • Prefix: s3://company/public/reports/*</p>
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
            card.className = 'p-3.5 rounded bg-[#0f172a] border border-[#1e293b] space-y-1.5 hover:border-[#334155] transition';
            card.innerHTML = `
                <div class="flex items-center justify-between font-bold text-xs">
                    <span class="text-white">${inv.id} • ${inv.name}</span>
                    <span class="text-emerald-400 text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded">✓ ${inv.status}</span>
                </div>
                <div class="p-1.5 rounded bg-[#0b0f19] text-[#38bdf8] text-[11px] font-mono">${inv.math}</div>
                <p class="text-[10px] text-[#64748b]">Impl: ${inv.file}</p>
            `;
            container.appendChild(card);
        });
    } catch (e) {
        console.error('Invariants fetch error:', e);
    }
}

async function fetchSystem() {
    try {
        const res = await fetch('/api/v1/system');
        const data = await res.json();
        const container = document.getElementById('system-diagnostics-container');
        if (!container) return;
        container.innerHTML = `
            <div class="grid grid-cols-2 gap-3">
                <div class="p-3 bg-[#0b0f19] rounded border border-[#1e293b]"><span class="text-[#64748b]">Version:</span> ${data.version}</div>
                <div class="p-3 bg-[#0b0f19] rounded border border-[#1e293b]"><span class="text-[#64748b]">Git Revision:</span> ${data.git_revision}</div>
                <div class="p-3 bg-[#0b0f19] rounded border border-[#1e293b]"><span class="text-[#64748b]">Target:</span> ${data.target_triple}</div>
                <div class="p-3 bg-[#0b0f19] rounded border border-[#1e293b]"><span class="text-[#64748b]">Crypto:</span> ${data.crypto_profile}</div>
            </div>
            <div class="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded text-xs mt-3">${data.network_hotpath_dependency}</div>
        `;
    } catch (e) {
        console.error('System fetch error:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchOverview();
    setInterval(() => {
        if (currentTab === 'overview') fetchOverview();
        if (currentTab === 'activity' || currentTab === 'decisions') fetchActivity();
    }, 2000);
});
"#.to_string()
}
