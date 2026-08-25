//! Stark pure monochrome design system with high-contrast Dark and Light modes.

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
.text-main { color: var(--text-main); }
.text-sub { color: var(--text-sub); }
.text-dim { color: var(--text-muted); }

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

[data-theme="dark"] .logo-light { display: none !important; }
[data-theme="dark"] .logo-dark { display: block !important; }
[data-theme="light"] .logo-light { display: block !important; }
[data-theme="light"] .logo-dark { display: none !important; }
"#
}
