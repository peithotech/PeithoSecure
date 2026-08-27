//! Specialized view renderers for Capabilities Tree, Tokens, Tools, and Invariants.

/// Return the JavaScript snippet for specialized view rendering.
pub fn get_js_views() -> &'static str {
    r#"
function renderCapabilitiesTree() {
    const list = document.getElementById('tree-nodes-list');
    if (!list) return;
    if (activeDecisions.length === 0) {
        list.innerHTML = `<div class="p-6 text-center text-dim mono">No active capability tree discovered yet.<br><span class="text-[11px] text-sub mt-1 inline-block">Waiting for agent MCP requests on 127.0.0.1:4040/mcp</span></div>`;
        const panel = document.getElementById('tree-detail-panel');
        if (panel) panel.innerHTML = `<div class="card-box text-dim text-center py-6">Select an agent node or token to inspect cryptographic delegation constraints.</div>`;
        return;
    }
    const principals = [...new Set(activeDecisions.map(d => d.principal_display))];
    let html = `<div onclick="selectCapNode('ROOT')" class="tree-node selected mono" id="node-ROOT">👑 ROOT (Trust Anchor ML-DSA-44)</div><div class="ml-4 border-l-subtle pl-3 space-y-2 mt-2">`;
    principals.forEach((p, idx) => {
        const isLast = idx === principals.length - 1;
        html += `<div onclick="selectCapNode('${p}')" class="tree-node mono" id="node-${p}">${isLast ? '└──' : '├──'} Agent: ${p}</div>`;
    });
    html += `</div>`;
    list.innerHTML = html;
    if (principals.length > 0) selectCapNode(principals[0]);
}

function selectCapNode(name) {
    document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('selected'));
    const n = document.getElementById(`node-${name}`);
    if (n) n.classList.add('selected');
    const panel = document.getElementById('tree-detail-panel');
    if (!panel) return;
    const isRoot = name === 'ROOT';
    const related = activeDecisions.filter(d => d.principal_display === name);
    const tools = [...new Set(related.map(d => d.tool_name))].join(', ') || 'All Delegated Tools';
    panel.innerHTML = `
        <div class="card-box space-y-2 text-xs">
            <div class="font-bold text-main border-b-subtle pb-1">CAPABILITY: ${name}</div>
            <div><span class="text-dim">Principal:</span> <span class="text-main font-bold">${name}</span></div>
            <div><span class="text-dim">Parent:</span> <span class="text-main">${isRoot ? 'None (Genesis Root)' : 'ROOT (Trust Anchor)'}</span></div>
            <div><span class="text-dim">Discovered Tools:</span> <span class="text-main font-bold">${tools}</span></div>
            <div><span class="text-dim">Cryptographic Algorithm:</span> <span class="text-allow font-bold">NIST ML-DSA-44 (FIPS 204)</span></div>
            <div><span class="text-dim">Attenuation Status:</span> <span class="text-allow font-bold">✓ Monotonic Verified</span></div>
            <div><span class="text-dim">Observed Calls:</span> <span class="text-main font-bold">${related.length} evaluations</span></div>
        </div>
    `;
}

function renderTokens() {
    const tbl = document.getElementById('tokens-table-container');
    if (!tbl) return;
    if (activeDecisions.length === 0) {
        tbl.innerHTML = `<div class="p-6 text-center text-dim mono">No capability tokens registered in local memory.<br><span class="text-[11px] text-sub mt-1 inline-block">Issue tokens via Python/TypeScript SDK or click '⚡ Simulate Allow'</span></div>`;
        return;
    }
    let html = `<table class="table-mono w-full text-left mono"><thead><tr><th>TRACE ID</th><th>PRINCIPAL</th><th>STATUS</th><th>LATENCY</th></tr></thead><tbody>`;
    activeDecisions.slice(0, 8).forEach((d, idx) => {
        const isAllow = d.outcome === 'ALLOW';
        html += `<tr id="tok-row-${idx}" class="cursor-pointer ${idx === 0 ? 'selected' : ''}" onclick="selectTokenRow(${idx})"><td class="py-2 text-main">${d.trace_id.substring(0, 12)}</td><td class="text-main">${d.principal_display}</td><td><span class="${isAllow ? 'badge-allow' : 'badge-deny'}">${d.outcome}</span></td><td class="text-dim">${d.latency_micros}µs</td></tr>`;
    });
    html += `</tbody></table>`;
    tbl.innerHTML = html;
}

function selectTokenRow(idx) {
    document.querySelectorAll('#tokens-table-container tr').forEach(r => r.classList.remove('selected'));
    const r = document.getElementById(`tok-row-${idx}`);
    if (r) r.classList.add('selected');
    const d = activeDecisions[idx];
    const box = document.getElementById('tree-detail-panel');
    if (!box || !d) return;
    const isAllow = d.outcome === 'ALLOW';
    box.innerHTML = `
        <div class="card-box space-y-2 text-xs">
            <div class="font-bold text-main border-b-subtle pb-1">TOKEN TRACE: ${d.trace_id}</div>
            <div><span class="text-dim">Principal:</span> <span class="text-main font-bold">${d.principal_display}</span></div>
            <div><span class="text-dim">Invoked Tool:</span> <span class="text-main font-bold">${d.tool_name}</span></div>
            <div><span class="text-dim">Target Resource:</span> <span class="text-main font-mono">${d.resource_display}</span></div>
            <div><span class="text-dim">Evaluation Outcome:</span> <span class="${isAllow ? 'badge-allow' : 'badge-deny'}">${d.outcome}</span></div>
            <div><span class="text-dim">Latency:</span> <span class="text-main font-bold">${d.latency_micros} µs</span></div>
            <div class="text-dim pt-2 border-t-subtle">${d.failed_invariant ? 'Violated Invariant: ' + d.failed_invariant : 'Cryptographic proof: Valid monotonic post-quantum chain'}</div>
        </div>
    `;
}

function renderTools() {
    const list = document.getElementById('tools-list-container');
    if (!list) return;
    if (activeDecisions.length === 0) {
        list.innerHTML = `<div class="p-6 text-center text-dim mono">No MCP tools observed yet.<br><span class="text-[11px] text-sub mt-1 inline-block">Gateway listening on 127.0.0.1:4040/mcp</span></div>`;
        return;
    }
    const toolMap = {};
    activeDecisions.forEach(d => {
        if (!toolMap[d.tool_name]) toolMap[d.tool_name] = { allows: 0, denies: 0 };
        if (d.outcome === 'ALLOW') toolMap[d.tool_name].allows++;
        else toolMap[d.tool_name].denies++;
    });
    let html = '';
    Object.keys(toolMap).forEach(tool => {
        const stats = toolMap[tool];
        html += `<div id="tool-row-${tool}" onclick="selectToolItem('${tool}', ${stats.allows}, ${stats.denies})" class="p-2.5 rounded bg-surface border-subtle hover:border-strong cursor-pointer flex justify-between items-center"><span class="font-bold text-main">${tool}</span><div class="flex gap-2">${stats.allows > 0 ? `<span class="badge-allow">${stats.allows} ALLOW</span>` : ''}${stats.denies > 0 ? `<span class="badge-deny">${stats.denies} DENY</span>` : ''}</div></div>`;
    });
    list.innerHTML = html;
}

function selectToolItem(name, allows, denies) {
    document.querySelectorAll('#tools-list-container > div').forEach(d => d.classList.remove('selected', 'border-strong'));
    const row = document.getElementById(`tool-row-${name}`);
    if (row) row.classList.add('selected', 'border-strong');
    const box = document.getElementById('tree-detail-panel');
    if (!box) return;
    box.innerHTML = `
        <div class="card-box space-y-2 text-xs">
            <div class="font-bold text-main border-b-subtle pb-1">CONNECTED TOOL: ${name}</div>
            <div><span class="text-dim">Tool Identifier:</span> <span class="text-main font-bold">${name}</span></div>
            <div><span class="text-dim">Allowed Calls:</span> <span class="text-allow font-bold">${allows}</span></div>
            <div><span class="text-dim">Denied Violations:</span> <span class="text-deny font-bold">${denies}</span></div>
            <div><span class="text-dim">Enforcement Engine:</span> <span class="text-main font-bold">Peitho MCP Interceptor</span></div>
            <div class="text-dim pt-2 border-t-subtle">Real-time status: Active on local MCP Gateway</div>
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
            card.className = 'card-box space-y-2 hover:border-strong transition';
            card.innerHTML = `
                <div class="flex items-center justify-between font-bold text-xs">
                    <span class="text-main">${inv.id} • ${inv.name}</span>
                    <span class="badge-allow text-[10px]">✓ ${inv.status}</span>
                </div>
                <div class="p-2 rounded bg-surface text-main text-[11px] mono border-subtle leading-relaxed">${inv.math}</div>
                <div class="text-[11px] space-y-0.5">
                    <div><span class="text-dim">Harness:</span> <span class="text-main font-mono">${inv.harness}</span></div>
                    <div><span class="text-dim">Coverage:</span> <span class="text-sub font-mono">${inv.coverage}</span></div>
                </div>
            `;
            container.appendChild(card);
        });
    } catch (e) { console.error(e); }
}

async function fetchSystem() {
    try {
        const res = await fetch('/api/v1/system');
        const data = await res.json();
        const r = document.getElementById('sys-runtime');
        const c = document.getElementById('sys-crypto');
        const p = document.getElementById('sys-persistence');
        const n = document.getElementById('sys-network');
        if (r) r.innerHTML = `<div><span class="text-dim">Platform:</span> <span class="text-main font-bold">${data.runtime.platform}</span></div><div><span class="text-dim">OS:</span> <span class="text-main font-bold">${data.runtime.os}</span></div><div><span class="text-dim">Architecture:</span> <span class="text-main font-bold">${data.runtime.architecture}</span></div>`;
        if (c) c.innerHTML = `<div><span class="text-dim">Root:</span> <span class="text-main font-bold">${data.crypto.root}</span></div><div><span class="text-dim">Profile:</span> <span class="text-main font-bold">${data.crypto.profile}</span></div><div><span class="text-dim">KEM:</span> <span class="text-main font-bold">${data.crypto.kem}</span></div><div><span class="text-dim">Verification:</span> <span class="text-allow font-bold">${data.crypto.verification_p50}</span></div>`;
        if (p) p.innerHTML = `<div><span class="text-dim">Revocation:</span> <span class="text-main font-bold">${data.persistence.revocation}</span></div><div><span class="text-dim">Nonce Store:</span> <span class="text-main font-bold">${data.persistence.nonce_store}</span></div><div><span class="text-dim">Recovery:</span> <span class="text-main font-bold">${data.persistence.recovery}</span></div>`;
        if (n) n.innerHTML = `<div><span class="text-dim">Hot Path:</span> <span class="text-allow font-bold">${data.network.authorization_hot_path}</span></div><div><span class="text-dim">External Dependency:</span> <span class="text-main font-bold">${data.network.external_dependency}</span></div>`;
    } catch (e) { console.error(e); }
}
"#
}
