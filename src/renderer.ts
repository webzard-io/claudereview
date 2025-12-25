import type { ParsedSession, ParsedMessage, SessionMetadata } from './types.ts';
import { BROWSER_CRYPTO_CODE } from './crypto.ts';

/**
 * Render a parsed session to self-contained HTML
 */
export function renderSessionToHtml(session: ParsedSession, options?: RenderOptions): string {
  const {
    encrypted = false,
    encryptedBlob,
    iv,
    salt,
  } = options || {};

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(session.title)} - Claude Code Session</title>
  ${renderOgTags(session)}
  <style>${CSS}</style>
</head>
<body>
  <div id="app">
    ${encrypted ? renderPasswordPrompt() : ''}
    <div id="viewer" class="${encrypted ? 'hidden' : ''}">
      ${renderHeader(session)}
      <main id="messages">
        ${encrypted ? '' : renderMessages(session.messages)}
      </main>
    </div>
  </div>

  ${encrypted ? `
  <script id="session-data" type="application/json">${JSON.stringify({
    encryptedBlob,
    iv,
    salt,
    metadata: session.metadata,
    title: session.title,
  })}</script>
  <script>${BROWSER_CRYPTO_CODE}</script>
  <script>${VIEWER_JS_ENCRYPTED}</script>
  ` : `
  <script id="session-data" type="application/json">${JSON.stringify(session)}</script>
  <script>${VIEWER_JS}</script>
  `}
</body>
</html>`;
}

interface RenderOptions {
  encrypted?: boolean;
  encryptedBlob?: string;
  iv?: string;
  salt?: string; // Only for private sessions
}

function renderOgTags(session: ParsedSession): string {
  const description = `${session.metadata.messageCount} messages · ${formatDuration(session.metadata.durationSeconds)} · Tools: ${formatToolUsage(session.metadata.tools)}`;

  return `
  <meta property="og:type" content="website">
  <meta property="og:title" content="Claude Session: ${escapeHtml(session.title)}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <meta property="og:site_name" content="claudereview.com">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="Claude Session: ${escapeHtml(session.title)}">
  <meta name="twitter:description" content="${escapeHtml(description)}">`;
}

function renderHeader(session: ParsedSession): string {
  return `
  <header>
    <div class="header-main">
      <div class="logo">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claude<span class="logo-accent">review</span></span>
      </div>
      <div class="session-id">${session.id.slice(0, 8)}</div>
    </div>
    <h1 class="session-title">${escapeHtml(session.title)}</h1>
    <div class="session-meta">
      <span class="meta-item">${session.metadata.messageCount} messages</span>
      <span class="meta-sep">·</span>
      <span class="meta-item">${formatDuration(session.metadata.durationSeconds)}</span>
      <span class="meta-sep">·</span>
      <span class="meta-item">${formatToolUsage(session.metadata.tools)}</span>
    </div>
  </header>`;
}

function renderPasswordPrompt(): string {
  return `
  <div id="password-prompt" class="password-prompt">
    <div class="prompt-box">
      <div class="prompt-icon">🔐</div>
      <h2>This session is password protected</h2>
      <p>Enter the password to view this session</p>
      <form id="password-form">
        <input type="password" id="password-input" placeholder="Password" autocomplete="off" autofocus>
        <button type="submit">Unlock</button>
      </form>
      <div id="password-error" class="error hidden"></div>
    </div>
  </div>`;
}

function renderMessages(messages: ParsedMessage[]): string {
  return messages.map((msg, index) => renderMessage(msg, index)).join('\n');
}

function renderMessage(message: ParsedMessage, index: number): string {
  switch (message.type) {
    case 'human':
      return renderHumanMessage(message, index);
    case 'assistant':
      return renderAssistantMessage(message, index);
    case 'tool_call':
      return renderToolCall(message, index);
    case 'tool_result':
      return renderToolResult(message, index);
    default:
      return '';
  }
}

function renderHumanMessage(message: ParsedMessage, index: number): string {
  return `
  <div class="message human" id="${message.id}" data-index="${index}">
    <div class="message-header">
      <span class="prompt-char">❯</span>
      <span class="message-time">${formatTime(message.timestamp)}</span>
      <button class="copy-link" title="Copy link to this message">🔗</button>
    </div>
    <div class="message-content">${escapeHtml(message.content)}</div>
  </div>`;
}

function renderAssistantMessage(message: ParsedMessage, index: number): string {
  let content = message.content;

  // If there are parts with tool calls, render them inline
  if (message.parts && message.parts.length > 0) {
    const partHtml = message.parts.map(part => {
      if (part.type === 'text') {
        return `<p>${escapeHtml(part.content || '')}</p>`;
      } else if (part.type === 'tool_call') {
        return renderInlineToolCall(part);
      }
      return '';
    }).join('\n');

    return `
    <div class="message assistant" id="${message.id}" data-index="${index}">
      <div class="message-content">${partHtml}</div>
    </div>`;
  }

  return `
  <div class="message assistant" id="${message.id}" data-index="${index}">
    <div class="message-content">${formatAssistantContent(content)}</div>
  </div>`;
}

function renderInlineToolCall(part: { toolName?: string; toolInput?: Record<string, unknown>; toolId?: string }): string {
  const name = part.toolName || 'Tool';
  const summary = formatToolSummary(name, part.toolInput);

  return `
  <div class="tool-call inline">
    <div class="tool-header">
      <span class="tool-name">${escapeHtml(name)}</span>
    </div>
    <div class="tool-summary">${escapeHtml(summary)}</div>
  </div>`;
}

function renderToolCall(message: ParsedMessage, index: number): string {
  const name = message.toolName || 'Tool';
  const summary = formatToolSummary(name, message.toolInput);

  return `
  <div class="message tool-call" id="${message.id}" data-index="${index}">
    <div class="tool-box">
      <div class="tool-header">
        <span class="tool-icon">${getToolIcon(name)}</span>
        <span class="tool-name">${escapeHtml(name)}</span>
        <span class="message-time">${formatTime(message.timestamp)}</span>
      </div>
      <div class="tool-summary">${escapeHtml(summary)}</div>
    </div>
  </div>`;
}

function renderToolResult(message: ParsedMessage, index: number): string {
  const output = message.toolOutput || message.content || '';
  const lines = output.split('\n');
  const isLong = lines.length > 10;
  const preview = isLong ? lines.slice(0, 5).join('\n') : output;
  const isError = message.isError;

  return `
  <div class="message tool-result ${isError ? 'error' : ''}" id="${message.id}" data-index="${index}">
    <div class="tool-output ${isLong ? 'collapsed' : ''}">
      <pre class="output-content">${escapeHtml(isLong ? preview : output)}</pre>
      ${isLong ? `
      <div class="output-expand" data-full="${escapeAttr(output)}">
        <button class="expand-btn">+ ${lines.length - 5} more lines</button>
      </div>
      ` : ''}
    </div>
  </div>`;
}

function formatToolSummary(name: string, input?: Record<string, unknown>): string {
  if (!input) return '';

  switch (name) {
    case 'Bash':
      return `$ ${input.command || ''}`;
    case 'Read':
      return `${input.file_path || ''}`;
    case 'Write':
      return `${input.file_path || ''}`;
    case 'Edit':
      return `${input.file_path || ''}`;
    case 'Glob':
      return `${input.pattern || ''}`;
    case 'Grep':
      return `${input.pattern || ''}`;
    case 'Task':
      return `${input.description || input.prompt?.toString().slice(0, 50) || ''}...`;
    default:
      return JSON.stringify(input).slice(0, 100);
  }
}

function getToolIcon(name: string): string {
  const icons: Record<string, string> = {
    'Bash': '⌘',
    'Read': '📄',
    'Write': '✏️',
    'Edit': '📝',
    'Glob': '🔍',
    'Grep': '🔎',
    'Task': '🤖',
    'WebFetch': '🌐',
    'WebSearch': '🔍',
  };
  return icons[name] || '⚙️';
}

function formatAssistantContent(content: string): string {
  // Basic markdown-like formatting
  return content
    .split('\n\n')
    .map(para => `<p>${escapeHtml(para).replace(/\n/g, '<br>')}</p>`)
    .join('\n');
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}min`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function formatToolUsage(tools: Record<string, number>): string {
  const entries = Object.entries(tools).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return 'no tools';
  if (entries.length <= 3) {
    return entries.map(([name, count]) => `${name} (${count})`).join(', ');
  }
  return entries.slice(0, 3).map(([name, count]) => `${name} (${count})`).join(', ') + '...';
}

function formatTime(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
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
    .replace(/>/g, '&gt;');
}

// CSS for the TUI-style viewer
const CSS = `
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --accent-muted: #388bfd;
  --green: #3fb950;
  --yellow: #d29922;
  --red: #f85149;
  --purple: #a371f7;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', Menlo, monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

#app {
  max-width: 900px;
  margin: 0 auto;
  padding: 2rem;
}

.hidden {
  display: none !important;
}

/* Header */
header {
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}

.header-main {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-icon {
  color: var(--accent);
  font-size: 1.25rem;
}

.logo-text {
  font-size: 1rem;
  font-weight: 500;
  color: var(--text-muted);
}

.logo-accent {
  color: var(--accent);
}

.session-id {
  font-size: 0.875rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
  background: var(--bg-secondary);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.session-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  font-family: var(--font-sans);
}

.session-meta {
  display: flex;
  gap: 0.5rem;
  color: var(--text-muted);
  font-size: 0.875rem;
}

.meta-sep {
  opacity: 0.5;
}

/* Messages */
#messages {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.message {
  position: relative;
}

.message:target,
.message.highlighted {
  animation: highlight 2s ease-out;
}

@keyframes highlight {
  0% { background: rgba(88, 166, 255, 0.2); }
  100% { background: transparent; }
}

/* Human messages */
.message.human {
  background: var(--bg-secondary);
  border-left: 3px solid var(--accent);
  padding: 1rem;
  border-radius: 0 8px 8px 0;
}

.message.human .message-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.prompt-char {
  color: var(--accent);
  font-weight: bold;
}

.message-time {
  color: var(--text-muted);
  font-size: 0.75rem;
  margin-left: auto;
}

.copy-link {
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.2s;
  font-size: 0.875rem;
}

.message:hover .copy-link {
  opacity: 1;
}

.copy-link:hover {
  color: var(--accent);
}

.message.human .message-content {
  color: var(--text-bright);
  white-space: pre-wrap;
}

/* Assistant messages */
.message.assistant {
  padding: 0.5rem 0 0.5rem 1rem;
  border-left: 1px solid var(--border);
}

.message.assistant .message-content {
  color: var(--text);
}

.message.assistant .message-content p {
  margin-bottom: 0.75rem;
}

.message.assistant .message-content p:last-child {
  margin-bottom: 0;
}

/* Tool calls */
.tool-box {
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}

.tool-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
}

.tool-icon {
  font-size: 0.875rem;
}

.tool-name {
  font-weight: 500;
  color: var(--purple);
  font-size: 0.875rem;
}

.tool-summary {
  padding: 0.5rem 0.75rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Tool results */
.message.tool-result {
  margin-left: 1rem;
}

.tool-output {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}

.output-content {
  padding: 0.75rem;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-muted);
  margin: 0;
  max-height: 400px;
  overflow-y: auto;
}

.message.tool-result.error .output-content {
  color: var(--red);
}

.output-expand {
  border-top: 1px solid var(--border);
  padding: 0.5rem;
  text-align: center;
}

.expand-btn {
  background: none;
  border: none;
  color: var(--accent);
  cursor: pointer;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
}

.expand-btn:hover {
  text-decoration: underline;
}

/* Inline tool calls */
.tool-call.inline {
  display: inline-block;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 4px;
  margin: 0.5rem 0;
}

.tool-call.inline .tool-header {
  padding: 0.25rem 0.5rem;
}

.tool-call.inline .tool-summary {
  padding: 0.25rem 0.5rem;
}

/* Password prompt */
.password-prompt {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 2rem;
}

.prompt-box {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 2rem;
  text-align: center;
  max-width: 400px;
  width: 100%;
}

.prompt-icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.prompt-box h2 {
  font-family: var(--font-sans);
  font-size: 1.25rem;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
}

.prompt-box p {
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}

.prompt-box form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.prompt-box input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  font-family: var(--font-mono);
  font-size: 1rem;
  color: var(--text);
}

.prompt-box input:focus {
  outline: none;
  border-color: var(--accent);
}

.prompt-box button {
  background: var(--accent);
  border: none;
  border-radius: 6px;
  padding: 0.75rem 1rem;
  font-family: var(--font-sans);
  font-size: 1rem;
  font-weight: 500;
  color: white;
  cursor: pointer;
  transition: background 0.2s;
}

.prompt-box button:hover {
  background: var(--accent-muted);
}

.error {
  color: var(--red);
  font-size: 0.875rem;
  margin-top: 1rem;
}

/* Scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: var(--bg);
}

::-webkit-scrollbar-thumb {
  background: var(--border);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted);
}

/* Responsive */
@media (max-width: 640px) {
  #app {
    padding: 1rem;
  }

  .session-meta {
    flex-wrap: wrap;
  }
}
`;

// JavaScript for the viewer (non-encrypted version)
const VIEWER_JS = `
document.addEventListener('DOMContentLoaded', function() {
  // Handle copy link buttons
  document.querySelectorAll('.copy-link').forEach(btn => {
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      const msg = this.closest('.message');
      const url = window.location.href.split('#')[0] + '#' + msg.id;
      navigator.clipboard.writeText(url).then(() => {
        this.textContent = '✓';
        setTimeout(() => { this.textContent = '🔗'; }, 1500);
      });
    });
  });

  // Handle expand buttons
  document.querySelectorAll('.expand-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const container = this.closest('.output-expand');
      const fullContent = container.dataset.full;
      const outputContent = container.previousElementSibling;
      outputContent.textContent = fullContent;
      container.remove();
    });
  });

  // Handle deep links
  if (window.location.hash) {
    const target = document.querySelector(window.location.hash);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      target.classList.add('highlighted');
    }
  }

  // Keyboard navigation
  let currentIndex = -1;
  const messages = document.querySelectorAll('.message');

  document.addEventListener('keydown', function(e) {
    if (e.key === 'j' || e.key === 'ArrowDown') {
      e.preventDefault();
      currentIndex = Math.min(currentIndex + 1, messages.length - 1);
      messages[currentIndex]?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else if (e.key === 'k' || e.key === 'ArrowUp') {
      e.preventDefault();
      currentIndex = Math.max(currentIndex - 1, 0);
      messages[currentIndex]?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else if (e.key === 'y') {
      // Copy current message link
      if (currentIndex >= 0) {
        const msg = messages[currentIndex];
        const url = window.location.href.split('#')[0] + '#' + msg.id;
        navigator.clipboard.writeText(url);
      }
    }
  });
});
`;

// JavaScript for encrypted viewer
const VIEWER_JS_ENCRYPTED = `
document.addEventListener('DOMContentLoaded', function() {
  const sessionData = JSON.parse(document.getElementById('session-data').textContent);
  const passwordPrompt = document.getElementById('password-prompt');
  const passwordForm = document.getElementById('password-form');
  const passwordInput = document.getElementById('password-input');
  const passwordError = document.getElementById('password-error');
  const viewer = document.getElementById('viewer');
  const messagesContainer = document.getElementById('messages');

  // Check if key is in URL fragment (public session)
  const hash = window.location.hash;
  const keyMatch = hash.match(/key=([^&]+)/);

  if (keyMatch && !sessionData.salt) {
    // Public session with key in URL
    const key = keyMatch[1];
    decryptAndRender(key);
  } else if (sessionData.salt) {
    // Private session - show password prompt
    passwordPrompt.classList.remove('hidden');
    passwordForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      const password = passwordInput.value;
      if (!password) return;

      passwordError.classList.add('hidden');
      try {
        await decryptAndRender(password);
      } catch (error) {
        passwordError.textContent = 'Incorrect password. Please try again.';
        passwordError.classList.remove('hidden');
        passwordInput.value = '';
        passwordInput.focus();
      }
    });
  }

  async function decryptAndRender(keyOrPassword) {
    const session = await decryptSession(
      sessionData.encryptedBlob,
      sessionData.iv,
      keyOrPassword,
      sessionData.salt
    );

    passwordPrompt?.classList.add('hidden');
    viewer.classList.remove('hidden');

    // Render messages
    messagesContainer.innerHTML = session.messages.map((msg, index) => renderMessage(msg, index)).join('');

    // Initialize viewer interactions
    initViewer();
  }

  function renderMessage(message, index) {
    switch (message.type) {
      case 'human':
        return \`
          <div class="message human" id="\${message.id}" data-index="\${index}">
            <div class="message-header">
              <span class="prompt-char">❯</span>
              <span class="message-time">\${formatTime(message.timestamp)}</span>
              <button class="copy-link" title="Copy link">🔗</button>
            </div>
            <div class="message-content">\${escapeHtml(message.content)}</div>
          </div>\`;
      case 'assistant':
        return \`
          <div class="message assistant" id="\${message.id}" data-index="\${index}">
            <div class="message-content">\${formatContent(message.content)}</div>
          </div>\`;
      case 'tool_call':
        return \`
          <div class="message tool-call" id="\${message.id}" data-index="\${index}">
            <div class="tool-box">
              <div class="tool-header">
                <span class="tool-icon">\${getToolIcon(message.toolName)}</span>
                <span class="tool-name">\${escapeHtml(message.toolName || 'Tool')}</span>
              </div>
              <div class="tool-summary">\${escapeHtml(message.content)}</div>
            </div>
          </div>\`;
      case 'tool_result':
        const output = message.toolOutput || message.content || '';
        return \`
          <div class="message tool-result \${message.isError ? 'error' : ''}" id="\${message.id}" data-index="\${index}">
            <div class="tool-output">
              <pre class="output-content">\${escapeHtml(output)}</pre>
            </div>
          </div>\`;
      default:
        return '';
    }
  }

  function formatTime(timestamp) {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch { return ''; }
  }

  function formatContent(content) {
    return content.split('\\n\\n').map(p => '<p>' + escapeHtml(p).replace(/\\n/g, '<br>') + '</p>').join('');
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function getToolIcon(name) {
    const icons = { Bash: '⌘', Read: '📄', Write: '✏️', Edit: '📝', Glob: '🔍', Grep: '🔎', Task: '🤖' };
    return icons[name] || '⚙️';
  }

  function initViewer() {
    // Copy link buttons
    document.querySelectorAll('.copy-link').forEach(btn => {
      btn.addEventListener('click', function(e) {
        e.preventDefault();
        const msg = this.closest('.message');
        const baseUrl = window.location.href.split('#')[0];
        const url = baseUrl + '#' + msg.id;
        navigator.clipboard.writeText(url).then(() => {
          this.textContent = '✓';
          setTimeout(() => { this.textContent = '🔗'; }, 1500);
        });
      });
    });

    // Deep links
    const targetId = window.location.hash.replace(/key=[^&]+&?/, '').replace('#', '');
    if (targetId) {
      const target = document.getElementById(targetId);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('highlighted');
      }
    }
  }
});
`;
