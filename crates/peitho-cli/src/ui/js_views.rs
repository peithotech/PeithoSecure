//! Specialized view renderers for Capabilities Tree, Tokens, Tools, and Invariants.

/// Return the JavaScript snippet for specialized view rendering.
pub fn get_js_views() -> &'static str {
    r#"
const capabilityData = {
    root: { subject: 'ROOT (Trust Anchor)', parent: 'None', authority: 'FULL', tools: 'search_documents, read_document, manage_secrets', resource: '*', expires: '31536000s', depth: '0 / 50', monotonic: '✓ Genesis', sig: '✓ ML-DSA-44 (FIPS 204)' },
    orchestrator: { subject: 'agent.orchestrator', parent: 'ROOT', authority: 'DELEGATE', tools: 'search_documents, read_document, manage_secrets', resource: 's3://enterprise/*', expires: '3600s', depth: '1 / 50', monotonic: '✓ Monotonic', sig: '✓ ML-DSA-44' },
    researcher: { subject: 'agent.researcher', parent: 'orchestrator', authority: 'READ', tools: 'search_documents, read_document', resource: 's3://knowledge/public/*', expires: '12.4s', depth: '2 / 50', monotonic: '✓ Monotonic', sig: '✓ SwarmSpeed' },
    finance: { subject: 'agent.finance', parent: 'orchestrator', authority: 'QUERY', tools: 'query_reports', resource: 'postgres://reports/*', expires: '60s', depth: '2 / 50', monotonic: '✓ Monotonic', sig: '✓ SwarmSpeed' }
};

function renderCapabilitiesTree() {
    const list = document.getElementById('tree-nodes-list');
    if (!list) return;
    list.innerHTML = `
        <div onclick="selectCap('root')" class="tree-node selected mono" id="node-root">👑 ROOT (Trust Anchor)</div>
        <div class="ml-4 border-l-subtle pl-3 space-y-2 mt-2">
            <div onclick="selectCap('orchestrator')" class="tree-node mono" id="node-orchestrator">├── Agent: orchestrator</div>
            <div class="ml-4 border-l-subtle pl-3 space-y-2 mt-2">
                <div onclick="selectCap('researcher')" class="tree-node mono" id="node-researcher">├── Agent: researcher (s3://knowledge/public/*)</div>
                <div onclick="selectCap('finance')" class="tree-node mono" id="node-finance">└── Agent: finance (postgres://reports/*)</div>
            </div>
        </div>
    `;
    selectCap('researcher');
}

function selectCap(key) {
    document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('selected'));
    const n = document.getElementById(`node-${key}`);
    if (n) n.classList.add('selected');
    const d = capabilityData[key];
    const panel = document.getElementById('tree-detail-panel');
    if (!panel || !d) return;
    panel.innerHTML = `
        <div class="card-box space-y-2 text-xs">
            <div class="font-bold text-main border-b-subtle pb-1">CAPABILITY: ${d.subject}</div>
            <div><span class="text-dim">Subject:</span> <span class="text-main font-bold">${d.subject}</span></div>
            <div><span class="text-dim">Parent:</span> <span class="text-main">${d.parent}</span></div>
            <div><span class="text-dim">Authority:</span> <span class="text-main font-bold">${d.authority}</span></div>
            <div><span class="text-dim">Tools:</span> <span class="text-main font-bold">${d.tools}</span></div>
            <div><span class="text-dim">Resource:</span> <span class="text-main font-mono">${d.resource}</span></div>
            <div><span class="text-dim">Expires:</span> <span class="text-main font-bold">${d.expires}</span></div>
            <div><span class="text-dim">Delegation Depth:</span> <span class="text-main font-bold">${d.depth}</span></div>
            <div><span class="text-dim">Attenuation:</span> <span class="text-allow font-bold">${d.monotonic}</span></div>
            <div><span class="text-dim">Signature:</span> <span class="text-allow font-bold">${d.sig}</span></div>
        </div>
    `;
}

function renderTokens() {
    const tbl = document.getElementById('tokens-table-container');
    if (!tbl) return;
    tbl.innerHTML = `
        <table class="table-mono w-full text-left mono">
            <thead><tr><th>ID</th><th>SUBJECT</th><th>STATUS</th><th>EXPIRES</th></tr></thead>
            <tbody>
                <tr id="tok-row-researcher" class="cursor-pointer selected" onclick="selectToken('researcher')"><td class="py-2 text-main">a91f...44b1</td><td class="text-main">researcher</td><td><span class="badge-allow">ACTIVE</span></td><td class="text-dim">11.2s</td></tr>
                <tr id="tok-row-worker" class="cursor-pointer" onclick="selectToken('worker')"><td class="py-2 text-main">b72c...99a0</td><td class="text-main">worker</td><td><span class="badge-deny">REVOKED</span></td><td class="text-dim">—</td></tr>
                <tr id="tok-row-analyst" class="cursor-pointer" onclick="selectToken('analyst')"><td class="py-2 text-main">c18a...ee12</td><td class="text-main">analyst</td><td><span class="badge-outline">BURNED</span></td><td class="text-dim">—</td></tr>
            </tbody>
        </table>
    `;
    selectToken('researcher');
}

function selectToken(key) {
    document.querySelectorAll('#tokens-table-container tr').forEach(r => r.classList.remove('selected'));
    const r = document.getElementById(`tok-row-${key}`);
    if (r) r.classList.add('selected');
    const box = document.getElementById('tree-detail-panel');
    if (!box) return;
    box.innerHTML = `
        <div class="card-box space-y-2 text-xs">
            <div class="font-bold text-main border-b-subtle pb-1">TOKEN REGISTRY: agent.${key}</div>
            <div><span class="text-dim">Subject:</span> <span class="text-main font-bold">agent.${key}</span></div>
            <div><span class="text-dim">Parent:</span> <span class="text-main">orchestrator</span></div>
            <div class="space-y-1 pt-1 border-t-subtle">
                <span class="text-dim font-bold">Cryptographic Caveats:</span>
                <div class="text-sub">✓ tool = search_documents, read_document</div>
                <div class="text-sub">✓ action = read</div>
                <div class="text-sub">✓ prefix = s3://knowledge/public/</div>
                <div class="text-sub">✓ budget = 100 µ-units</div>
            </div>
            <div><span class="text-dim">Nonce:</span> <span class="text-main font-mono">7f9a88c2...</span></div>
            <div><span class="text-dim">State:</span> <span class="${key === 'worker' ? 'badge-deny' : 'badge-allow'}">${key === 'worker' ? 'REVOKED' : (key === 'analyst' ? 'BURNED' : 'ACTIVE')}</span></div>
        </div>
    `;
}

function renderTools() {
    const list = document.getElementById('tools-list-container');
    if (!list) return;
    list.innerHTML = `
        <div id="tool-row-search_documents" onclick="selectTool('search_documents', 'ALLOW')" class="p-2.5 rounded bg-surface border-subtle hover:border-strong cursor-pointer flex justify-between"><span class="font-bold text-main">search_documents</span><span class="badge-allow">ALLOW 892</span></div>
        <div id="tool-row-read_document" onclick="selectTool('read_document', 'ALLOW')" class="p-2.5 rounded bg-surface border-subtle hover:border-strong cursor-pointer flex justify-between"><span class="font-bold text-main">read_document</span><span class="badge-allow">ALLOW 641</span></div>
        <div id="tool-row-manage_secrets" onclick="selectTool('manage_secrets', 'DENY')" class="p-2.5 rounded bg-surface border-subtle hover:border-strong cursor-pointer flex justify-between"><span class="font-bold text-main">manage_secrets</span><span class="badge-deny">DENY 31</span></div>
        <div id="tool-row-execute_wire_transfer" onclick="selectTool('execute_wire_transfer', 'DENY')" class="p-2.5 rounded bg-surface border-subtle hover:border-strong cursor-pointer flex justify-between"><span class="font-bold text-main">execute_wire_transfer</span><span class="badge-deny">DENY 12</span></div>
    `;
}

function selectTool(name, status) {
    document.querySelectorAll('#tools-list-container > div').forEach(d => d.classList.remove('selected', 'border-strong'));
    const row = document.getElementById(`tool-row-${name}`);
    if (row) row.classList.add('selected', 'border-strong');
    const box = document.getElementById('tree-detail-panel');
    if (!box) return;
    box.innerHTML = `
        <div class="card-box space-y-2 text-xs">
            <div class="font-bold text-main border-b-subtle pb-1">TOOL INTERCEPTION: ${name}</div>
            <div><span class="text-dim">Required Capability:</span> <span class="text-main font-bold">capability.${name}</span></div>
            <div><span class="text-dim">Principal:</span> <span class="text-main font-bold">agent.researcher</span></div>
            <div><span class="text-dim">Enforcement Result:</span> <span class="${status === 'ALLOW' ? 'badge-allow' : 'badge-deny'}">${status} ${status === 'DENY' ? '/ P-005 Tool Scope' : ''}</span></div>
            <div class="text-dim pt-2 border-t-subtle">Interception reason: ${status === 'ALLOW' ? 'Agent holds valid cryptographic proof and non-revoked delegation token.' : 'Agent lacks signed delegation for this tool boundary.'}</div>
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
