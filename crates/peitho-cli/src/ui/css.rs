//! Stark pure monochrome design system with selective Red/Green for security actions and outcomes.

/// Return the complete CSS stylesheet string.
pub fn get_stylesheet() -> &'static str {
    r#"
:root {
    --bg: #ffffff;
    --bg-surface: #f4f4f5;
    --bg-surface-hover: #e4e4e7;
    --border: #e4e4e7;
    --border-strong: #18181b;
    --text-main: #09090b;
    --text-sub: #52525b;
    --text-muted: #71717a;
    --badge-bg: #18181b;
    --badge-text: #ffffff;
    --color-allow: #10b981;
    --color-allow-bg: rgba(16, 185, 129, 0.08);
    --color-allow-border: rgba(16, 185, 129, 0.25);
    --color-deny: #f43f5e;
    --color-deny-bg: rgba(244, 63, 94, 0.08);
    --color-deny-border: rgba(244, 63, 94, 0.25);
    --font-mono: 'JetBrains Mono', monospace;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

[data-theme="dark"] {
    --bg: #000000;
    --bg-surface: #0a0a0c;
    --bg-surface-hover: #141416;
    --border: #262626;
    --border-strong: #ffffff;
    --text-main: #fafafa;
    --text-sub: #a1a1aa;
    --text-muted: #71717a;
    --badge-bg: #ffffff;
    --badge-text: #000000;
    --color-allow: #34d399;
    --color-allow-bg: rgba(52, 211, 153, 0.12);
    --color-allow-border: rgba(52, 211, 153, 0.3);
    --color-deny: #fb7185;
    --color-deny-bg: rgba(251, 113, 133, 0.12);
    --color-deny-border: rgba(251, 113, 133, 0.3);
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background-color: var(--bg);
    color: var(--text-main);
    font-family: var(--font-sans);
    line-height: 1.5;
    transition: background-color 0.15s ease, color 0.15s ease;
}

.mono { font-family: var(--font-mono); }
.bg-app { background-color: var(--bg); }
.bg-surface { background-color: var(--bg-surface); }
.border-subtle { border: 1px solid var(--border); }
.border-b-subtle { border-bottom: 1px solid var(--border); }
.border-t-subtle { border-top: 1px solid var(--border); }
.border-l-subtle { border-left: 1px solid var(--border); }
.text-main { color: var(--text-main); }
.text-sub { color: var(--text-sub); }
.text-dim { color: var(--text-muted); }

.text-allow { color: var(--color-allow); }
.text-deny { color: var(--color-deny); }

.badge-mono {
    background-color: var(--badge-bg);
    color: var(--badge-text);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-outline {
    border: 1px solid var(--border);
    color: var(--text-main);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
}

.badge-allow {
    background-color: var(--color-allow-bg);
    color: var(--color-allow);
    border: 1px solid var(--color-allow-border);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

.badge-deny {
    background-color: var(--color-deny-bg);
    color: var(--color-deny);
    border: 1px solid var(--color-deny-border);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

.btn-mono {
    background-color: var(--bg-surface);
    color: var(--text-main);
    border: 1px solid var(--border);
    padding: 6px 14px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    font-family: var(--font-mono);
    transition: all 0.15s ease;
}
.btn-mono:hover {
    background-color: var(--bg-surface-hover);
    border-color: var(--border-strong);
}

.btn-allow {
    border-color: var(--color-allow-border);
    color: var(--color-allow);
}
.btn-allow:hover {
    background-color: var(--color-allow-bg);
    border-color: var(--color-allow);
}

.btn-deny {
    border-color: var(--color-deny-border);
    color: var(--color-deny);
}
.btn-deny:hover {
    background-color: var(--color-deny-bg);
    border-color: var(--color-deny);
}

.pill-btn {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-sub);
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-family: var(--font-mono);
    cursor: pointer;
    transition: all 0.15s ease;
}
.pill-btn:hover {
    border-color: var(--border-strong);
    color: var(--text-main);
}
.pill-btn.active {
    background-color: var(--badge-bg);
    color: var(--badge-text);
    border-color: var(--badge-bg);
}

.tab-btn {
    background: transparent;
    border: none;
    padding: 10px 16px;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-sub);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    font-family: var(--font-mono);
    transition: all 0.15s ease;
}
.tab-btn.active {
    color: var(--text-main);
    font-weight: 700;
    border-bottom-color: var(--border-strong);
}

.card-box {
    background-color: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
}

.tree-node {
    cursor: pointer;
    padding: 6px 10px;
    border-radius: 4px;
    transition: all 0.1s ease;
}
.tree-node:hover {
    background-color: var(--bg-surface-hover);
}
.tree-node.selected {
    border: 1px solid var(--border-strong);
    background-color: var(--bg-surface-hover);
}

.table-mono {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}
.table-mono th {
    text-align: left;
    padding: 8px 12px;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    font-size: 11px;
}
.table-mono td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    transition: background-color 0.1s ease;
}
.table-mono tr:hover td {
    background-color: var(--bg-surface-hover);
}
.table-mono tr.selected td {
    background-color: var(--bg-surface-hover);
    font-weight: 600;
}

.scroll-box {
    max-height: 480px;
    overflow-y: auto;
    overflow-x: auto;
}
.scroll-box::-webkit-scrollbar { width: 5px; height: 5px; }
.scroll-box::-webkit-scrollbar-track { background: transparent; }
.scroll-box::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
.scroll-box::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

[data-theme="dark"] .logo-light { display: none !important; }
[data-theme="dark"] .logo-dark { display: block !important; }
[data-theme="light"] .logo-light { display: block !important; }
[data-theme="light"] .logo-dark { display: none !important; }
"#
}
