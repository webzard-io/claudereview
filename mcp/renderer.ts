/**
 * Renderer for MCP - generates full-featured HTML viewer
 * This is a bundled version of the CLI's renderer.ts
 */

interface ParsedMessage {
  id: string;
  type: 'human' | 'assistant' | 'tool_call' | 'tool_result';
  content: string;
  timestamp: string;
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
  toolOutput?: string;
  isError?: boolean;
}

interface SessionMetadata {
  messageCount: number;
  toolCount: number;
  durationSeconds: number;
  startTime: string;
  endTime: string;
  tools: Record<string, number>;
}

interface ParsedSession {
  id: string;
  title: string;
  messages: ParsedMessage[];
  metadata: SessionMetadata;
}

export function renderSessionToHtml(session: ParsedSession): string {
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(session.title)} | claudereview</title>
  ${renderOgTags(session)}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>${CSS}${LIGHT_MODE_CSS}</style>
</head>
<body>
  <div id="app">
    <!-- Search overlay -->
    <div id="search-overlay" class="search-overlay hidden">
      <div class="search-box">
        <span class="search-icon">⌘F</span>
        <input type="text" id="search-input" placeholder="Search in session..." autocomplete="off">
        <span id="search-count" class="search-count"></span>
        <button id="search-prev" class="search-nav" title="Previous (↑)">↑</button>
        <button id="search-next" class="search-nav" title="Next (↓)">↓</button>
        <button id="search-close" class="search-close" title="Close (Esc)">×</button>
      </div>
    </div>

    <!-- Main viewer -->
    <div id="viewer">
      ${renderHeader(session)}

      <div class="session-container">
        <main id="messages" class="messages">
          ${renderMessages(session.messages)}
        </main>
      </div>

      <footer class="viewer-footer">
        <div class="footer-hint">
          <kbd>⌘</kbd><kbd>F</kbd> search
          <span class="sep">·</span>
          <kbd>C</kbd> collapse all
        </div>
        <a href="https://claudereview.com" class="footer-brand" target="_blank">
          <span class="brand-icon">◈</span> claudereview
        </a>
      </footer>
    </div>
  </div>

  <script id="session-data" type="application/json">${escapeJsonForHtml(JSON.stringify(session))}</script>
  <script>${VIEWER_JS}</script>
</body>
</html>`;
}

function renderOgTags(session: ParsedSession): string {
  const toolList = Object.entries(session.metadata.tools)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([name, count]) => `${name}×${count}`)
    .join(' ');

  const description = `${session.metadata.messageCount} messages · ${formatDuration(session.metadata.durationSeconds)}${toolList ? ` · ${toolList}` : ''}`;

  return `
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escapeHtml(truncate(session.title, 60))}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <meta property="og:site_name" content="claudereview">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${escapeHtml(truncate(session.title, 60))}">
  <meta name="twitter:description" content="${escapeHtml(description)}">
  <meta name="theme-color" content="#0a0a0a">`;
}

function renderHeader(session: ParsedSession): string {
  const toolsSummary = Object.entries(session.metadata.tools)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => `<span class="tool-badge">${escapeHtml(name)}<span class="tool-count">${count}</span></span>`)
    .join('');

  return `
  <header class="viewer-header">
    <div class="header-top">
      <a href="https://claudereview.com" class="logo" target="_blank">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claudereview</span>
      </a>
      <div class="header-actions">
        <button id="theme-toggle" class="action-btn labeled" title="Toggle theme">
          <span class="action-icon theme-icon">◐</span>
          <span class="action-label">Theme</span>
        </button>
        <button id="collapse-all-btn" class="action-btn labeled" title="Collapse all">
          <span class="action-icon">−</span>
          <span class="action-label">Collapse</span>
        </button>
        <button id="expand-all-btn" class="action-btn labeled" title="Expand all">
          <span class="action-icon">+</span>
          <span class="action-label">Expand</span>
        </button>
        <button id="copy-link-btn" class="action-btn labeled" title="Copy link">
          <span class="action-icon">⎘</span>
          <span class="action-label">Copy</span>
        </button>
      </div>
    </div>

    <div class="session-info">
      <h1 class="session-title">${escapeHtml(truncate(session.title, 120))}</h1>
      <div class="session-meta">
        <span class="meta-item">
          <span class="meta-icon">💬</span>
          ${session.metadata.messageCount} messages
        </span>
        <span class="meta-item">
          <span class="meta-icon">⏱</span>
          ${formatDuration(session.metadata.durationSeconds)}
        </span>
        <span class="meta-item session-id">
          ${session.id.slice(0, 8)}
        </span>
      </div>
      ${toolsSummary ? `<div class="tools-used">${toolsSummary}</div>` : ''}
    </div>
  </header>`;
}

function renderMessages(messages: ParsedMessage[]): string {
  const groups = groupMessages(messages);
  return groups.map((group, idx) => renderMessageGroup(group, idx)).join('\n');
}

interface MessageGroup {
  type: 'human' | 'assistant';
  messages: ParsedMessage[];
}

function groupMessages(messages: ParsedMessage[]): MessageGroup[] {
  const groups: MessageGroup[] = [];
  let currentGroup: MessageGroup | null = null;

  for (const msg of messages) {
    const groupType = msg.type === 'human' ? 'human' : 'assistant';

    if (!currentGroup || currentGroup.type !== groupType) {
      if (currentGroup) groups.push(currentGroup);
      currentGroup = { type: groupType, messages: [] };
    }
    currentGroup.messages.push(msg);
  }

  if (currentGroup) groups.push(currentGroup);
  return groups;
}

function renderMessageGroup(group: MessageGroup, index: number): string {
  if (group.type === 'human') {
    return group.messages.map(msg => renderHumanMessage(msg)).join('\n');
  } else {
    return `
    <div class="assistant-group" data-group="${index}">
      <div class="assistant-indicator">
        <span class="indicator-icon">●</span>
        <span class="indicator-text">Claude</span>
      </div>
      <div class="assistant-content">
        ${group.messages.map(msg => renderAssistantItem(msg)).join('\n')}
      </div>
    </div>`;
  }
}

function renderHumanMessage(message: ParsedMessage): string {
  const content = message.content || '';
  const isLong = content.length > 500;

  return `
  <div class="message human-message" id="${message.id}">
    <div class="message-gutter">
      <span class="human-prompt">❯</span>
    </div>
    <div class="message-body">
      <div class="human-content ${isLong ? 'collapsible collapsed' : ''}">
        ${formatContent(content)}
      </div>
      ${isLong ? `<button class="expand-toggle" data-target="${message.id}">Show more ↓</button>` : ''}
      <div class="message-meta">
        <span class="meta-time">${formatTime(message.timestamp)}</span>
      </div>
    </div>
  </div>`;
}

function renderAssistantItem(message: ParsedMessage): string {
  switch (message.type) {
    case 'assistant':
      return renderAssistantText(message);
    case 'tool_call':
      return renderToolCall(message);
    case 'tool_result':
      return renderToolResult(message);
    default:
      return '';
  }
}

function renderAssistantText(message: ParsedMessage): string {
  const content = message.content || '';
  if (!content.trim()) return '';

  return `
  <div class="assistant-text" id="${message.id}">
    ${formatContent(content)}
  </div>`;
}

function renderToolCall(message: ParsedMessage): string {
  const name = message.toolName || 'Tool';
  const icon = getToolIcon(name);
  const summary = formatToolSummary(name, message.toolInput);

  return `
  <div class="tool-call" id="${message.id}" data-tool-name="${escapeHtml(name)}">
    <div class="tool-header">
      <span class="tool-icon">${icon}</span>
      <span class="tool-name">${escapeHtml(name)}</span>
      <span class="tool-summary">${escapeHtml(summary)}</span>
    </div>
  </div>`;
}

function renderToolResult(message: ParsedMessage): string {
  const output = message.toolOutput || message.content || '';
  const lines = output.split('\n');
  const lineCount = lines.length;
  const isLong = lineCount > 15;
  const isError = message.isError;

  const preview = isLong ? lines.slice(0, 10).join('\n') : output;

  return `
  <div class="tool-result ${isError ? 'error' : ''} ${isLong ? 'collapsible collapsed' : ''}" id="${message.id}">
    <div class="result-content">
      <pre class="output-pre"><code>${escapeHtml(isLong ? preview : output)}</code></pre>
    </div>
    ${isLong ? `
    <div class="result-expand" data-full="${escapeAttr(output)}">
      <button class="expand-btn">↓ ${lineCount - 10} more lines</button>
    </div>
    ` : ''}
  </div>`;
}

function formatToolSummary(name: string, input?: Record<string, unknown>): string {
  if (!input) return '';

  switch (name) {
    case 'Bash':
      const cmd = String(input.command || '');
      return cmd.length > 80 ? cmd.slice(0, 80) + '...' : cmd;
    case 'Read':
      return String(input.file_path || '');
    case 'Write':
      return String(input.file_path || '');
    case 'Edit':
      return String(input.file_path || '');
    case 'Glob':
      return String(input.pattern || '');
    case 'Grep':
      return String(input.pattern || '');
    case 'Task':
      return String(input.description || '').slice(0, 60);
    default:
      const str = JSON.stringify(input);
      return str.length > 60 ? str.slice(0, 60) + '...' : str;
  }
}

function getToolIcon(name: string): string {
  const icons: Record<string, string> = {
    'Bash': '$',
    'Read': '◇',
    'Write': '◆',
    'Edit': '✎',
    'Glob': '⊛',
    'Grep': '⊙',
    'Task': '⊳',
    'WebFetch': '↗',
    'WebSearch': '◎',
    'TodoWrite': '☑',
  };
  return icons[name] || '⊡';
}

function formatContent(content: string): string {
  if (!content) return '';

  let result = '';
  let remaining = content;

  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    const textBefore = content.slice(lastIndex, match.index);
    result += formatTextContent(textBefore);

    const language = match[1] || 'plaintext';
    const code = match[2] || '';
    result += `<pre class="code-block"><code class="language-${language}">${escapeHtml(code.trim())}</code></pre>`;

    lastIndex = match.index + match[0].length;
  }

  result += formatTextContent(content.slice(lastIndex));
  return result;
}

function formatTextContent(text: string): string {
  if (!text) return '';

  let escaped = escapeHtml(text);
  escaped = escaped.replace(/`([^`]+)`/g, (_, code) => {
    return `<code class="inline-code">${code}</code>`;
  });

  return escaped
    .split('\n\n')
    .map(para => {
      if (!para.trim()) return '';
      return `<p>${para.replace(/\n/g, '<br>')}</p>`;
    })
    .filter(p => p)
    .join('\n');
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function formatTime(timestamp: string): string {
  try {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  } catch {
    return '';
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '&#10;');
}

function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return str.slice(0, max - 1) + '…';
}

function escapeJsonForHtml(jsonStr: string): string {
  return jsonStr
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
}

// ============================================================================
// CSS
// ============================================================================

const CSS = `
:root {
  --bg-primary: #0a0a0a;
  --bg-secondary: #111111;
  --bg-tertiary: #1a1a1a;
  --bg-elevated: #222222;
  --text-primary: #e0e0e0;
  --text-secondary: #888888;
  --text-muted: #555555;
  --text-bright: #ffffff;
  --accent-green: #4ec970;
  --accent-blue: #5c9fd7;
  --accent-purple: #b38bff;
  --accent-yellow: #e6c07b;
  --accent-red: #e06c75;
  --accent-cyan: #56c8d8;
  --accent-orange: #d19a66;
  --human-accent: var(--accent-green);
  --claude-accent: var(--accent-purple);
  --tool-accent: var(--accent-blue);
  --error-accent: var(--accent-red);
  --border-subtle: #2a2a2a;
  --border-medium: #3a3a3a;
  --font-mono: 'JetBrains Mono', 'SF Mono', Menlo, monospace;
  --font-size-xs: 11px;
  --font-size-sm: 12px;
  --font-size-base: 13px;
  --font-size-lg: 14px;
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --transition-fast: 0.15s ease;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; -webkit-font-smoothing: antialiased; }
body { font-family: var(--font-mono); font-size: var(--font-size-base); line-height: 1.6; color: var(--text-primary); background: var(--bg-primary); min-height: 100vh; }
#app { min-height: 100vh; display: flex; flex-direction: column; }
.hidden { display: none !important; }

/* Search */
.search-overlay { position: fixed; top: 0; left: 0; right: 0; z-index: 1000; padding: var(--space-4); background: linear-gradient(to bottom, var(--bg-primary) 0%, transparent 100%); animation: slideDown 0.2s ease; }
@keyframes slideDown { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.search-box { max-width: 600px; margin: 0 auto; display: flex; align-items: center; gap: var(--space-2); background: var(--bg-tertiary); border: 1px solid var(--border-medium); border-radius: var(--radius-md); padding: var(--space-2) var(--space-3); }
.search-icon { color: var(--text-muted); font-size: var(--font-size-xs); background: var(--bg-secondary); padding: 2px 6px; border-radius: 3px; }
.search-box input { flex: 1; background: transparent; border: none; color: var(--text-primary); font-family: var(--font-mono); font-size: var(--font-size-base); outline: none; }
.search-count { color: var(--text-secondary); font-size: var(--font-size-xs); }
.search-nav, .search-close { background: transparent; border: none; color: var(--text-secondary); cursor: pointer; padding: var(--space-1); font-family: var(--font-mono); font-size: var(--font-size-sm); }
.search-nav:hover, .search-close:hover { color: var(--text-primary); }

/* Header */
.viewer-header { position: sticky; top: 0; z-index: 50; background: var(--bg-primary); border-bottom: 1px solid var(--border-subtle); padding: var(--space-4) var(--space-5); }
.header-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-3); }
.logo { display: flex; align-items: center; gap: var(--space-2); text-decoration: none; color: var(--text-secondary); }
.logo:hover { color: var(--text-primary); }
.logo-icon { color: var(--accent-purple); font-size: 18px; }
.logo-text { font-size: var(--font-size-sm); font-weight: 500; }
.header-actions { display: flex; gap: var(--space-2); }
.action-btn { background: var(--bg-tertiary); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: var(--space-1) var(--space-2); color: var(--text-secondary); cursor: pointer; font-size: var(--font-size-sm); }
.action-btn:hover { background: var(--bg-elevated); color: var(--text-primary); border-color: var(--border-medium); }
.action-btn.labeled { display: flex; align-items: center; gap: var(--space-1); }
.action-label { font-size: var(--font-size-xs); }
.session-info { max-width: 800px; }
.session-title { font-size: var(--font-size-lg); font-weight: 600; color: var(--text-bright); margin-bottom: var(--space-2); line-height: 1.4; }
.session-meta { display: flex; flex-wrap: wrap; gap: var(--space-3); font-size: var(--font-size-xs); color: var(--text-secondary); }
.meta-item { display: flex; align-items: center; gap: var(--space-1); }
.meta-icon { opacity: 0.7; }
.session-id { font-family: var(--font-mono); background: var(--bg-tertiary); padding: 2px 6px; border-radius: 3px; color: var(--text-muted); }
.tools-used { display: flex; flex-wrap: wrap; gap: var(--space-2); margin-top: var(--space-3); }
.tool-badge { display: inline-flex; align-items: center; gap: var(--space-1); background: var(--bg-tertiary); padding: 6px 12px; border-radius: var(--radius-sm); font-size: var(--font-size-sm); font-weight: 500; color: var(--tool-accent); }
.tool-count { color: var(--text-muted); margin-left: 3px; font-weight: 600; }

/* Messages */
.session-container { flex: 1; padding: var(--space-5); max-width: 900px; margin: 0 auto; width: 100%; }
.messages { display: flex; flex-direction: column; gap: var(--space-5); }

/* Human */
.human-message { display: flex; gap: var(--space-3); }
.message-gutter { flex-shrink: 0; width: 20px; padding-top: 2px; }
.human-prompt { color: var(--human-accent); font-weight: 700; font-size: 16px; }
.message-body { flex: 1; min-width: 0; }
.human-content { color: var(--text-bright); font-weight: 500; }
.human-content.collapsed { max-height: 200px; overflow: hidden; position: relative; }
.human-content.collapsed::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 60px; background: linear-gradient(transparent, var(--bg-primary)); }
.expand-toggle { background: transparent; border: none; color: var(--accent-blue); font-family: var(--font-mono); font-size: var(--font-size-xs); cursor: pointer; padding: var(--space-2) 0; }
.message-meta { display: flex; align-items: center; gap: var(--space-2); margin-top: var(--space-2); }
.meta-time { font-size: var(--font-size-xs); color: var(--text-muted); }

/* Assistant */
.assistant-group { display: flex; gap: var(--space-3); }
.assistant-indicator { flex-shrink: 0; width: 20px; display: flex; flex-direction: column; align-items: center; gap: var(--space-1); padding-top: 4px; }
.indicator-icon { color: var(--claude-accent); font-size: 8px; }
.indicator-text { writing-mode: vertical-rl; text-orientation: mixed; font-size: 9px; color: var(--text-muted); letter-spacing: 1px; text-transform: uppercase; }
.assistant-content { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: var(--space-3); padding-left: var(--space-3); border-left: 1px solid var(--border-subtle); }
.assistant-text { color: var(--text-primary); line-height: 1.7; }
.assistant-text p { margin-bottom: var(--space-3); }
.assistant-text p:last-child { margin-bottom: 0; }
.assistant-text .code-block { background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: var(--space-3); margin: var(--space-3) 0; overflow-x: auto; font-size: var(--font-size-sm); }
.assistant-text .inline-code { background: var(--bg-tertiary); padding: 2px 6px; border-radius: 3px; font-size: 0.9em; color: var(--accent-orange); }

/* Tool call */
.tool-call { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-2); padding: var(--space-2) 0; }
.tool-icon { color: var(--tool-accent); font-weight: 700; font-size: 14px; }
.tool-name { color: var(--tool-accent); font-weight: 600; font-size: var(--font-size-sm); }
.tool-summary { color: var(--text-secondary); font-size: var(--font-size-sm); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }
.tool-header { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-2); }

/* Tool result */
.tool-result { background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); overflow: hidden; }
.tool-result.error { border-color: rgba(224, 108, 117, 0.3); }
.tool-result.error .output-pre { color: var(--error-accent); }
.result-content { max-height: 400px; overflow: auto; }
.tool-result.collapsed .result-content { max-height: 60px; overflow: hidden; position: relative; }
.tool-result.collapsed .result-content::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 40px; background: linear-gradient(transparent, var(--bg-secondary)); pointer-events: none; }
.output-pre { margin: 0; padding: var(--space-3); font-size: var(--font-size-sm); line-height: 1.5; white-space: pre-wrap; word-break: break-word; color: var(--text-secondary); }
.result-expand { border-top: 1px solid var(--border-subtle); padding: var(--space-2); text-align: center; }
.expand-btn { background: transparent; border: none; color: var(--accent-blue); font-family: var(--font-mono); font-size: var(--font-size-xs); cursor: pointer; }

/* Footer */
.viewer-footer { position: sticky; bottom: 0; display: flex; align-items: center; justify-content: space-between; padding: var(--space-3) var(--space-5); background: var(--bg-secondary); border-top: 1px solid var(--border-subtle); font-size: var(--font-size-xs); color: var(--text-muted); }
.footer-hint { display: flex; align-items: center; gap: var(--space-2); }
.footer-hint kbd { background: var(--bg-tertiary); padding: 2px 5px; border-radius: 3px; font-size: 10px; }
.footer-hint .sep { opacity: 0.3; }
.footer-brand { display: flex; align-items: center; gap: var(--space-1); color: var(--text-muted); text-decoration: none; }
.footer-brand:hover { color: var(--text-secondary); }
.brand-icon { color: var(--accent-purple); }

/* Search highlight */
.search-match { background: rgba(230, 192, 123, 0.3); border-radius: 2px; }
.search-match.current { background: rgba(230, 192, 123, 0.6); }

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-secondary); }
::-webkit-scrollbar-thumb { background: var(--border-medium); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

/* Responsive */
@media (max-width: 640px) {
  .viewer-header { padding: var(--space-3); }
  .session-container { padding: var(--space-3); }
  .session-title { font-size: var(--font-size-base); }
  .footer-hint { display: none; }
  .assistant-indicator { display: none; }
  .assistant-content { padding-left: 0; border-left: none; }
  .action-label { display: none; }
}
`;

const LIGHT_MODE_CSS = `
[data-theme="light"] {
  --bg-primary: #ffffff;
  --bg-secondary: #f8f9fa;
  --bg-tertiary: #f1f3f4;
  --bg-elevated: #e8eaed;
  --text-primary: #1f2937;
  --text-secondary: #4b5563;
  --text-muted: #9ca3af;
  --text-bright: #111827;
  --accent-green: #059669;
  --accent-blue: #2563eb;
  --accent-purple: #7c3aed;
  --accent-yellow: #d97706;
  --accent-red: #dc2626;
  --accent-cyan: #0891b2;
  --accent-orange: #ea580c;
  --border-subtle: #e5e7eb;
  --border-medium: #d1d5db;
}
[data-theme="light"] .human-content.collapsed::after { background: linear-gradient(transparent, var(--bg-primary)); }
`;

// ============================================================================
// Viewer JavaScript
// ============================================================================

const VIEWER_JS = `
(function() {
  // Theme toggle
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('ccshare-theme', next);
  });

  // Restore saved theme
  const savedTheme = localStorage.getItem('ccshare-theme');
  if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);

  // Collapse/expand buttons
  document.getElementById('collapse-all-btn')?.addEventListener('click', () => {
    document.querySelectorAll('.tool-result').forEach(el => el.classList.add('collapsed'));
  });

  document.getElementById('expand-all-btn')?.addEventListener('click', () => {
    document.querySelectorAll('.tool-result').forEach(el => el.classList.remove('collapsed'));
  });

  // Expand buttons for tool results
  document.querySelectorAll('.expand-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const result = btn.closest('.tool-result');
      result.classList.remove('collapsed');
      const fullContent = btn.closest('.result-expand').dataset.full;
      if (fullContent) result.querySelector('code').textContent = fullContent;
      btn.closest('.result-expand').remove();
    });
  });

  // Expand toggle for human messages
  document.querySelectorAll('.expand-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const messageBody = btn.closest('.message-body');
      const content = messageBody?.querySelector('.human-content');
      if (content && content.classList.contains('collapsed')) {
        content.classList.remove('collapsed');
        btn.textContent = 'Show less ↑';
      } else if (content) {
        content.classList.add('collapsed');
        btn.textContent = 'Show more ↓';
      }
    });
  });

  // Copy link button
  document.getElementById('copy-link-btn')?.addEventListener('click', () => {
    navigator.clipboard.writeText(window.location.href);
    const btn = document.getElementById('copy-link-btn');
    const label = btn?.querySelector('.action-label');
    if (label) {
      label.textContent = 'Copied!';
      setTimeout(() => label.textContent = 'Copy', 1500);
    }
  });

  // Search
  const searchOverlay = document.getElementById('search-overlay');
  const searchInput = document.getElementById('search-input');
  let searchMatches = [];
  let currentMatch = -1;

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
      e.preventDefault();
      searchOverlay.classList.remove('hidden');
      searchInput.focus();
      searchInput.select();
    }
    if (e.key === 'Escape') {
      searchOverlay.classList.add('hidden');
      clearSearch();
    }
    if (e.key === 'c' && !e.metaKey && !e.ctrlKey && document.activeElement.tagName !== 'INPUT') {
      document.querySelectorAll('.tool-result').forEach(el => el.classList.add('collapsed'));
    }
    if (e.key === 'e' && !e.metaKey && !e.ctrlKey && document.activeElement.tagName !== 'INPUT') {
      document.querySelectorAll('.tool-result').forEach(el => el.classList.remove('collapsed'));
    }
  });

  searchInput?.addEventListener('input', () => performSearch(searchInput.value));
  document.getElementById('search-close')?.addEventListener('click', () => {
    searchOverlay.classList.add('hidden');
    clearSearch();
  });
  document.getElementById('search-next')?.addEventListener('click', () => navigateSearch(1));
  document.getElementById('search-prev')?.addEventListener('click', () => navigateSearch(-1));

  function performSearch(query) {
    clearSearch();
    if (!query || query.length < 2) {
      document.getElementById('search-count').textContent = '';
      return;
    }

    const regex = new RegExp('(' + query.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + ')', 'gi');
    const walker = document.createTreeWalker(
      document.getElementById('messages'),
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    const matches = [];
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (node.textContent.match(regex)) {
        const span = document.createElement('span');
        span.innerHTML = node.textContent.replace(regex, '<mark class="search-match">$1</mark>');
        node.parentNode.replaceChild(span, node);
        span.querySelectorAll('.search-match').forEach(m => matches.push(m));
      }
    }

    searchMatches = matches;
    currentMatch = -1;
    document.getElementById('search-count').textContent = matches.length + ' found';
    if (matches.length) navigateSearch(1);
  }

  function navigateSearch(dir) {
    if (!searchMatches.length) return;
    if (currentMatch >= 0) searchMatches[currentMatch].classList.remove('current');
    currentMatch = (currentMatch + dir + searchMatches.length) % searchMatches.length;
    searchMatches[currentMatch].classList.add('current');
    searchMatches[currentMatch].scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function clearSearch() {
    document.querySelectorAll('.search-match').forEach(el => {
      const text = el.textContent;
      el.replaceWith(text);
    });
    searchMatches = [];
    currentMatch = -1;
  }

  // Handle deep link on load
  if (window.location.hash && !window.location.hash.includes('key=')) {
    const target = document.querySelector(window.location.hash);
    if (target) setTimeout(() => target.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
  }
})();
`;
