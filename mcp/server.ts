#!/usr/bin/env bun
/**
 * claudereview MCP Server
 *
 * Exposes tools for sharing Claude Code sessions via the Model Context Protocol.
 *
 * Tools:
 * - list_sessions: List available Claude Code sessions
 * - share_session: Share a session and get a URL
 * - preview_session: Generate a local HTML preview
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readdir, stat, readFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { renderSessionToHtml } from './renderer.ts';
import type { ParsedSession, ParsedMessage, SessionMetadata } from './types.ts';

const CLAUDE_PROJECTS_DIR = join(homedir(), '.claude', 'projects');
const CODEX_SESSIONS_DIR = join(homedir(), '.codex', 'sessions');
const API_URL = process.env.CCSHARE_API_URL || process.env.CLAUDEREVIEW_API_URL || 'https://claudereview.com';
const API_KEY = process.env.CCSHARE_API_KEY;

// Session discovery
interface LocalSession {
  id: string;
  path: string;
  projectPath: string;
  modifiedAt: Date;
  title?: string;
  source: 'claude' | 'codex';
}

async function listSessions(limit = 10): Promise<LocalSession[]> {
  const claudeSessions = await listClaudeSessions();
  const codexSessions = await listCodexSessions();
  const allSessions = [...claudeSessions, ...codexSessions];
  allSessions.sort((a, b) => b.modifiedAt.getTime() - a.modifiedAt.getTime());
  return allSessions.slice(0, limit);
}

async function listClaudeSessions(): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    const projectDirs = await readdir(CLAUDE_PROJECTS_DIR);

    for (const projectDir of projectDirs) {
      const projectPath = join(CLAUDE_PROJECTS_DIR, projectDir);
      const projectStat = await stat(projectPath);

      if (!projectStat.isDirectory()) continue;

      const files = await readdir(projectPath);
      const sessionFiles = files.filter(f => f.endsWith('.jsonl'));

      for (const file of sessionFiles) {
        const filePath = join(projectPath, file);
        const fileStat = await stat(filePath);
        const id = file.replace('.jsonl', '');

        // Try to get title
        let title: string | undefined;
        try {
          const content = await readFile(filePath, 'utf-8');
          const firstLine = content.split('\n')[0];
          if (firstLine) {
            const parsed = JSON.parse(firstLine);
            if (parsed.type === 'summary' && parsed.summary) {
              title = parsed.summary;
            }
          }
        } catch {}

        sessions.push({
          id,
          path: filePath,
          projectPath: '/' + projectDir.replace(/^-/, '').replace(/-/g, '/'),
          modifiedAt: fileStat.mtime,
          title,
          source: 'claude',
        });
      }
    }

    return sessions;
  } catch {
    return [];
  }
}

async function listCodexSessions(): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    const years = await readdir(CODEX_SESSIONS_DIR);

    for (const year of years) {
      const yearPath = join(CODEX_SESSIONS_DIR, year);
      let yearStat;
      try { yearStat = await stat(yearPath); } catch { continue; }
      if (!yearStat.isDirectory()) continue;

      const months = await readdir(yearPath);
      for (const month of months) {
        const monthPath = join(yearPath, month);
        let monthStat;
        try { monthStat = await stat(monthPath); } catch { continue; }
        if (!monthStat.isDirectory()) continue;

        const days = await readdir(monthPath);
        for (const day of days) {
          const dayPath = join(monthPath, day);
          let dayStat;
          try { dayStat = await stat(dayPath); } catch { continue; }
          if (!dayStat.isDirectory()) continue;

          const files = await readdir(dayPath);
          for (const file of files.filter(f => f.endsWith('.jsonl'))) {
            const filePath = join(dayPath, file);
            const fileStat = await stat(filePath);

            const idMatch = file.match(/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.jsonl$/i);
            const id = idMatch?.[1] ?? file.replace('.jsonl', '');

            let projectPath = '';
            try {
              const content = await readFile(filePath, 'utf-8');
              const firstLine = content.split('\n')[0];
              if (firstLine) {
                const parsed = JSON.parse(firstLine);
                if (parsed.type === 'session_meta' && parsed.payload?.cwd) {
                  projectPath = parsed.payload.cwd;
                }
              }
            } catch {}

            sessions.push({
              id,
              path: filePath,
              projectPath,
              modifiedAt: fileStat.mtime,
              source: 'codex',
            });
          }
        }
      }
    }

    return sessions;
  } catch {
    return [];
  }
}

async function getSessionContent(sessionId: string): Promise<{ content: string; source: 'claude' | 'codex' } | null> {
  const sessions = await listSessions(100);
  const session = sessions.find(s => s.id === sessionId || s.id.startsWith(sessionId));
  if (!session) return null;
  const content = await readFile(session.path, 'utf-8');
  return { content, source: session.source };
}

function isCodexFormat(content: string): boolean {
  const firstLine = content.split('\n')[0];
  if (!firstLine) return false;
  try {
    const parsed = JSON.parse(firstLine);
    return parsed.type === 'session_meta' && parsed.payload?.originator?.includes('codex');
  } catch {
    return false;
  }
}

function parseSessionContent(content: string, sessionId: string, source: 'claude' | 'codex', customTitle?: string): ParsedSession {
  if (source === 'codex') {
    return parseCodexContent(content, sessionId, customTitle);
  }
  return parseClaudeContent(content, sessionId, customTitle);
}

function parseClaudeContent(content: string, sessionId: string, customTitle?: string): ParsedSession {
  const lines = content.trim().split('\n').filter(line => line.trim());
  const messages: ParsedMessage[] = [];
  let title = customTitle || 'Untitled Session';
  const timestamps: number[] = [];
  const toolCounts: Record<string, number> = {};
  let messageIndex = 0;

  const filesCreated = new Set<string>();
  const filesModified = new Set<string>();
  const commandsRun: string[] = [];
  let totalChars = 0;

  for (const line of lines) {
    try {
      const raw = JSON.parse(line);

      if (raw.type === 'summary' && raw.summary && !customTitle) {
        title = raw.summary;
        continue;
      }

      if (raw.type === 'file-history-snapshot') continue;
      if (!raw.message) continue;

      const timestamp = raw.timestamp || new Date().toISOString();
      if (raw.timestamp) {
        timestamps.push(new Date(raw.timestamp).getTime());
      }

      if (raw.type === 'user') {
        if (typeof raw.message.content === 'string') {
          totalChars += raw.message.content.length;
          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'human',
            content: raw.message.content,
            timestamp,
          });
        } else if (Array.isArray(raw.message.content)) {
          for (const block of raw.message.content) {
            if (block.type === 'tool_result') {
              let output = '';
              if (raw.toolUseResult?.stdout) output = raw.toolUseResult.stdout;
              if (raw.toolUseResult?.stderr) output += (output ? '\n' : '') + raw.toolUseResult.stderr;
              if (!output && typeof block.content === 'string') output = block.content;

              totalChars += output.length;
              messages.push({
                id: `msg-${messageIndex++}`,
                type: 'tool_result',
                content: output,
                timestamp,
                toolId: block.tool_use_id,
                toolOutput: output,
                isError: block.is_error,
              });
            }
          }
        }
      } else if (raw.type === 'assistant' && Array.isArray(raw.message.content)) {
        for (const block of raw.message.content) {
          if (block.type === 'thinking') continue;

          if (block.type === 'text' && block.text) {
            totalChars += block.text.length;
            messages.push({
              id: `msg-${messageIndex++}`,
              type: 'assistant',
              content: block.text,
              timestamp,
            });
          } else if (block.type === 'tool_use') {
            toolCounts[block.name] = (toolCounts[block.name] || 0) + 1;

            const input = block.input as Record<string, unknown> | undefined;
            if (block.name === 'Write' && input?.file_path) {
              filesCreated.add(String(input.file_path));
            }
            if (block.name === 'Edit' && input?.file_path) {
              filesModified.add(String(input.file_path));
            }
            if (block.name === 'Bash' && input?.command) {
              const cmd = String(input.command);
              if (!cmd.match(/^(cd|ls|pwd|echo|cat|head|tail)\b/) && cmd.length < 100) {
                commandsRun.push(cmd);
              }
            }

            messages.push({
              id: `msg-${messageIndex++}`,
              type: 'tool_call',
              content: formatToolCall(block.name, block.input),
              timestamp,
              toolName: block.name,
              toolInput: block.input,
              toolId: block.id,
            });
          }
        }
      }
    } catch {}
  }

  if (title === 'Untitled Session') {
    const firstHuman = messages.find(m => m.type === 'human');
    if (firstHuman) {
      title = firstHuman.content.slice(0, 100) + (firstHuman.content.length > 100 ? '...' : '');
    }
  }

  const startTime = timestamps.length > 0 ? new Date(Math.min(...timestamps)).toISOString() : new Date().toISOString();
  const endTime = timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : new Date().toISOString();
  const durationSeconds = timestamps.length >= 2 ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000) : 0;

  return {
    id: sessionId,
    title,
    messages,
    metadata: {
      messageCount: messages.filter(m => m.type === 'human' || m.type === 'assistant').length,
      toolCount: Object.values(toolCounts).reduce((a, b) => a + b, 0),
      durationSeconds,
      startTime,
      endTime,
      tools: toolCounts,
      filesCreated: [...filesCreated].slice(0, 20),
      filesModified: [...filesModified].slice(0, 20),
      commandsRun: commandsRun.slice(0, 15),
      estimatedTokens: Math.round(totalChars / 4),
    },
    source: 'claude',
  };
}

function parseCodexContent(content: string, sessionId: string, customTitle?: string): ParsedSession {
  const lines = content.trim().split('\n').filter(line => line.trim());
  const messages: ParsedMessage[] = [];
  let title = customTitle || 'Untitled Codex Session';
  const timestamps: number[] = [];
  const toolCounts: Record<string, number> = {};
  let messageIndex = 0;

  const filesCreated = new Set<string>();
  const filesModified = new Set<string>();
  const commandsRun: string[] = [];
  let totalChars = 0;

  // Codex-specific metadata
  let model: string | undefined;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  for (const line of lines) {
    try {
      const raw = JSON.parse(line);

      if (raw.timestamp) {
        const ts = new Date(raw.timestamp).getTime();
        if (!isNaN(ts)) timestamps.push(ts);
      }

      if (raw.type === 'turn_context' && raw.payload?.model) {
        model = raw.payload.model;
      }

      if (raw.type === 'event_msg' && raw.payload?.type === 'token_count' && raw.payload?.info?.total_token_usage) {
        totalInputTokens = raw.payload.info.total_token_usage.input_tokens;
        totalOutputTokens = raw.payload.info.total_token_usage.output_tokens;
      }

      if (raw.type === 'response_item' && raw.payload) {
        const item = raw.payload;

        if (item.type === 'message') {
          if (item.role === 'user') {
            const userText = item.content
              ?.filter((c: { type: string; text?: string }) => c.type === 'input_text' && !c.text?.includes('<environment_context>'))
              .map((c: { text?: string }) => c.text)
              .join('\n');

            if (userText?.trim()) {
              totalChars += userText.length;
              messages.push({
                id: `msg-${messageIndex++}`,
                type: 'human',
                content: userText.trim(),
                timestamp: raw.timestamp,
              });
            }
          } else if (item.role === 'assistant') {
            const assistantText = item.content
              ?.filter((c: { type: string }) => c.type === 'output_text')
              .map((c: { text?: string }) => c.text)
              .join('\n');

            if (assistantText?.trim()) {
              totalChars += assistantText.length;
              messages.push({
                id: `msg-${messageIndex++}`,
                type: 'assistant',
                content: assistantText.trim(),
                timestamp: raw.timestamp,
              });
            }
          }
        } else if (item.type === 'function_call' && item.name && item.call_id) {
          const toolName = mapCodexToolName(item.name);
          const toolInput = parseCodexToolInput(item.name, item.arguments);

          toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;

          if (toolName === 'Bash' && toolInput?.command) {
            const cmd = String(toolInput.command);
            totalChars += cmd.length;
            if (!cmd.match(/^(cd|ls|pwd|echo|cat|head|tail)\b/) && cmd.length < 100) {
              commandsRun.push(cmd);
            }
          }
          if (toolName === 'Write' && toolInput?.file_path) {
            filesCreated.add(String(toolInput.file_path));
          }
          if (toolName === 'Edit' && toolInput?.file_path) {
            filesModified.add(String(toolInput.file_path));
          }

          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'tool_call',
            content: formatToolCall(toolName, toolInput),
            timestamp: raw.timestamp,
            toolName,
            toolInput,
            toolId: item.call_id,
          });
        } else if (item.type === 'function_call_output' && item.call_id) {
          let output = '';
          let isError = false;
          try {
            const parsed = JSON.parse(item.output || '{}');
            output = parsed.output || '';
            isError = parsed.metadata?.exit_code !== 0;
          } catch {
            output = item.output || '';
          }

          totalChars += output.length;
          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'tool_result',
            content: output,
            timestamp: raw.timestamp,
            toolId: item.call_id,
            toolOutput: output,
            isError,
          });
        }
      }
    } catch {}
  }

  if (title === 'Untitled Codex Session') {
    const firstHuman = messages.find(m => m.type === 'human');
    if (firstHuman) {
      title = firstHuman.content.slice(0, 100) + (firstHuman.content.length > 100 ? '...' : '');
    }
  }

  const startTime = timestamps.length > 0 ? new Date(Math.min(...timestamps)).toISOString() : new Date().toISOString();
  const endTime = timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : new Date().toISOString();
  const durationSeconds = timestamps.length >= 2 ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000) : 0;

  return {
    id: sessionId,
    title,
    messages,
    metadata: {
      messageCount: messages.filter(m => m.type === 'human' || m.type === 'assistant').length,
      toolCount: Object.values(toolCounts).reduce((a, b) => a + b, 0),
      durationSeconds,
      startTime,
      endTime,
      tools: toolCounts,
      filesCreated: [...filesCreated].slice(0, 20),
      filesModified: [...filesModified].slice(0, 20),
      commandsRun: commandsRun.slice(0, 15),
      estimatedTokens: totalInputTokens + totalOutputTokens || Math.round(totalChars / 4),
      model,
      actualInputTokens: totalInputTokens || undefined,
      actualOutputTokens: totalOutputTokens || undefined,
    },
    source: 'codex',
  };
}

function mapCodexToolName(codexName: string): string {
  const mapping: Record<string, string> = {
    'shell': 'Bash',
    'read_file': 'Read',
    'write_file': 'Write',
    'edit_file': 'Edit',
    'list_files': 'LS',
    'search': 'Grep',
  };
  return mapping[codexName] || codexName;
}

function parseCodexToolInput(toolName: string, argsJson?: string): Record<string, unknown> | undefined {
  if (!argsJson) return undefined;
  try {
    const args = JSON.parse(argsJson);
    if (toolName === 'shell' && Array.isArray(args.command)) {
      const cmdArray = args.command as string[];
      if (cmdArray[0] === 'bash' && cmdArray[1] === '-lc' && cmdArray[2]) {
        return { command: cmdArray[2] };
      }
      return { command: cmdArray.join(' ') };
    }
    return args;
  } catch {
    return undefined;
  }
}

function formatToolCall(name: string, input?: Record<string, unknown>): string {
  if (!input) return name;
  if (name === 'Bash' && input.command) return `$ ${input.command}`;
  if (name === 'Read' && input.file_path) return `read ${input.file_path}`;
  if (name === 'Write' && input.file_path) return `write ${input.file_path}`;
  if (name === 'Edit' && input.file_path) return `edit ${input.file_path}`;
  return `${name}: ${JSON.stringify(input)}`;
}

function formatSessionAsMarkdown(session: ParsedSession): string {
  const lines: string[] = [];

  lines.push(`# ${session.title}`);
  lines.push('');
  lines.push('## Session Info');
  lines.push('');
  lines.push(`- **Source**: ${session.source === 'codex' ? 'Codex CLI' : 'Claude Code'}`);
  lines.push(`- **Messages**: ${session.metadata.messageCount}`);
  lines.push(`- **Duration**: ${formatDuration(session.metadata.durationSeconds)}`);
  lines.push(`- **Tools Used**: ${session.metadata.toolCount}`);

  if (session.metadata.actualInputTokens) {
    const total = session.metadata.actualInputTokens + (session.metadata.actualOutputTokens || 0);
    lines.push(`- **Tokens**: ${Math.round(total / 1000)}K (${session.metadata.actualInputTokens.toLocaleString()} in, ${(session.metadata.actualOutputTokens || 0).toLocaleString()} out)`);
  } else if (session.metadata.estimatedTokens) {
    lines.push(`- **Tokens**: ~${Math.round(session.metadata.estimatedTokens / 1000)}K (estimated)`);
  }

  if (session.metadata.model) {
    lines.push(`- **Model**: ${session.metadata.model}`);
  }

  if (session.metadata.gitRepo || session.metadata.gitBranch) {
    lines.push('');
    lines.push('### Git Context');
    if (session.metadata.gitRepo) lines.push(`- **Repo**: ${session.metadata.gitRepo}`);
    if (session.metadata.gitBranch) lines.push(`- **Branch**: ${session.metadata.gitBranch}`);
    if (session.metadata.gitCommit) lines.push(`- **Commit**: \`${session.metadata.gitCommit.slice(0, 7)}\``);
  }

  if (Object.keys(session.metadata.tools).length > 0) {
    lines.push('');
    lines.push('### Tools Summary');
    for (const [tool, count] of Object.entries(session.metadata.tools).sort((a, b) => b[1] - a[1])) {
      lines.push(`- ${tool}: ${count}x`);
    }
  }

  const { filesCreated, filesModified, commandsRun } = session.metadata;
  const hasKeyMoments = (filesCreated?.length || 0) + (filesModified?.length || 0) + (commandsRun?.length || 0) > 0;

  if (hasKeyMoments) {
    lines.push('');
    lines.push('### Key Moments');

    if (filesCreated && filesCreated.length > 0) {
      lines.push('');
      lines.push('**Files Created:**');
      for (const file of filesCreated.slice(0, 10)) {
        lines.push(`- \`${file.split('/').pop()}\``);
      }
      if (filesCreated.length > 10) lines.push(`- ...and ${filesCreated.length - 10} more`);
    }

    if (filesModified && filesModified.length > 0) {
      lines.push('');
      lines.push('**Files Modified:**');
      for (const file of filesModified.slice(0, 10)) {
        lines.push(`- \`${file.split('/').pop()}\``);
      }
      if (filesModified.length > 10) lines.push(`- ...and ${filesModified.length - 10} more`);
    }

    if (commandsRun && commandsRun.length > 0) {
      lines.push('');
      lines.push('**Commands Run:**');
      for (const cmd of commandsRun.slice(0, 5)) {
        lines.push(`- \`${cmd}\``);
      }
      if (commandsRun.length > 5) lines.push(`- ...and ${commandsRun.length - 5} more`);
    }
  }

  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Conversation');
  lines.push('');

  for (const msg of session.messages) {
    if (msg.type === 'human') {
      lines.push(`### User\n\n${msg.content}\n`);
    } else if (msg.type === 'assistant') {
      lines.push(`### Assistant\n\n${msg.content}\n`);
    } else if (msg.type === 'tool_call') {
      lines.push(`**Tool: ${msg.toolName}**\n\n\`\`\`\n${msg.content}\n\`\`\`\n`);
    } else if (msg.type === 'tool_result') {
      const output = msg.toolOutput || msg.content;
      const truncatedOutput = output.length > 2000 ? output.slice(0, 2000) + '\n... (truncated)' : output;
      const errorLabel = msg.isError ? ' (error)' : '';
      lines.push(`<details>\n<summary>Tool Output${errorLabel}</summary>\n\n\`\`\`\n${truncatedOutput}\n\`\`\`\n</details>\n`);
    }
  }

  lines.push('---');
  lines.push(`*Exported from [claudereview](https://claudereview.com) on ${new Date().toISOString().split('T')[0]}*`);

  return lines.join('\n');
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

// Simple encryption (matching the CLI)
function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function encrypt(data: string, key: Uint8Array): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', key.buffer as ArrayBuffer, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoder.encode(data));

  return {
    ciphertext: Buffer.from(encrypted).toString('base64url'),
    iv: Buffer.from(iv).toString('base64url'),
  };
}

async function shareSession(sessionId: string, title?: string): Promise<{ url: string } | { error: string }> {
  const result = await getSessionContent(sessionId);
  if (!result) {
    return { error: `Session not found: ${sessionId}` };
  }

  // Parse session into structured format (matching CLI parser)
  const parsedSession = parseSessionContent(result.content, sessionId, result.source, title);

  // Render session to full HTML (matching CLI)
  const renderedHtml = renderSessionToHtml(parsedSession);

  // Create payload with both HTML and session data (like CLI does)
  const payload = JSON.stringify({
    html: renderedHtml,
    session: {
      id: parsedSession.id,
      title: parsedSession.title,
      metadata: parsedSession.metadata,
      messages: parsedSession.messages,
    },
  });

  // Encrypt the payload
  const key = generateKey();
  const { ciphertext, iv } = await encrypt(payload, key);

  const { messageCount, toolCount, durationSeconds } = parsedSession.metadata;

  // Upload
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (API_KEY) {
      headers['Authorization'] = `Bearer ${API_KEY}`;
    }

    const response = await fetch(`${API_URL}/api/upload`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        encryptedBlob: ciphertext,
        iv,
        visibility: 'public',
        metadata: {
          title: parsedSession.title.slice(0, 200),
          messageCount,
          toolCount,
          durationSeconds,
        },
      }),
    });

    if (!response.ok) {
      return { error: `Upload failed: ${response.statusText}` };
    }

    const result = await response.json() as { id: string; url: string };
    const keyBase64 = Buffer.from(key).toString('base64url');
    return { url: `${result.url}#key=${keyBase64}` };
  } catch (err) {
    return { error: `Upload failed: ${err}` };
  }
}

// MCP Server setup
const server = new Server(
  { name: 'claudereview', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'list_sessions',
      description: `List available Claude Code sessions from ~/.claude/projects.

Returns the most recent sessions with:
- Session ID (use for sharing)
- Title (from session summary)
- Project path
- Last modified time
- Source (Claude Code or Codex)

Example: list_sessions(limit: 5)`,
      inputSchema: {
        type: 'object',
        properties: {
          limit: {
            type: 'number',
            description: 'Maximum number of sessions to return (default: 10)',
          },
        },
      },
    },
    {
      name: 'share_session',
      description: `Share a Claude Code session to claudereview.com with full-featured viewer.

Creates an E2E encrypted link with:
- TUI-style dark/light theme viewer
- Search overlay (⌘F)
- Collapsible tool outputs
- Syntax highlighted code blocks
- Diff view for file edits
- Key moments summary (files created/modified, commands run)
- Git context (repo, branch, commit)
- Clickable tool badges to jump to instances
- Token/cost estimates
- Deep linking to specific messages
- OG meta tags for link previews

The encryption key is embedded in the URL fragment (#key=xxx) and never sent to the server.

Set CCSHARE_API_KEY environment variable to link sessions to your account and manage them in the dashboard.

Example: share_session(session_id: "last", title: "Bug fix for auth")`,
      inputSchema: {
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session ID to share. Use "last" for the most recent session, or provide the session ID from list_sessions.',
          },
          title: {
            type: 'string',
            description: 'Custom title for the shared session. If not provided, uses the session summary.',
          },
        },
        required: ['session_id'],
      },
    },
    {
      name: 'copy_session',
      description: `Copy a session as formatted Markdown text.

Returns the session content as Markdown with:
- Session info (source, messages, duration, tokens)
- Git context if available
- Tools summary
- Key moments (files created/modified, commands run)
- Full conversation with user/assistant/tool messages

Use this when you want to paste session content somewhere rather than sharing a URL.

Example: copy_session(session_id: "last")`,
      inputSchema: {
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session ID to copy. Use "last" for the most recent session, or provide the session ID from list_sessions.',
          },
        },
        required: ['session_id'],
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === 'list_sessions') {
    const limit = (args?.limit as number) || 10;
    const sessions = await listSessions(limit);

    const formatted = sessions.map((s, i) => {
      const sourceLabel = s.source === 'codex' ? '[Codex]' : '[Claude]';
      return `${i + 1}. ${sourceLabel} [${s.id.slice(0, 8)}] ${s.title || 'Untitled'}\n   Project: ${s.projectPath}\n   Modified: ${s.modifiedAt.toLocaleString()}`;
    }).join('\n\n');

    return {
      content: [{ type: 'text', text: formatted || 'No sessions found.' }],
    };
  }

  if (name === 'share_session') {
    let sessionId = args?.session_id as string;
    const title = args?.title as string | undefined;

    if (sessionId === 'last') {
      const sessions = await listSessions(1);
      if (sessions.length === 0) {
        return { content: [{ type: 'text', text: 'No sessions found.' }] };
      }
      sessionId = sessions[0]!.id;
    }

    const result = await shareSession(sessionId, title);

    if ('error' in result) {
      return { content: [{ type: 'text', text: `Error: ${result.error}` }] };
    }

    const authNote = API_KEY
      ? 'This session is linked to your account.'
      : '⚠️ No API key configured - session shared anonymously. Set CCSHARE_API_KEY to link sessions to your account.';

    return {
      content: [{ type: 'text', text: `Session shared successfully!\n\nURL: ${result.url}\n\nThis link is encrypted. Only people with this exact URL can view the session.\n\n${authNote}` }],
    };
  }

  if (name === 'copy_session') {
    let sessionId = args?.session_id as string;

    if (sessionId === 'last') {
      const sessions = await listSessions(1);
      if (sessions.length === 0) {
        return { content: [{ type: 'text', text: 'No sessions found.' }] };
      }
      sessionId = sessions[0]!.id;
    }

    const result = await getSessionContent(sessionId);
    if (!result) {
      return { content: [{ type: 'text', text: `Session not found: ${sessionId}` }] };
    }

    const parsedSession = parseSessionContent(result.content, sessionId, result.source);
    const markdown = formatSessionAsMarkdown(parsedSession);

    return {
      content: [{ type: 'text', text: markdown }],
    };
  }

  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('claudereview MCP server running');
}

main().catch(console.error);
