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

const CLAUDE_PROJECTS_DIR = join(homedir(), '.claude', 'projects');
const API_URL = process.env.CLAUDEREVIEW_API_URL || 'https://claudereview.com';

// Session discovery
interface LocalSession {
  id: string;
  path: string;
  projectPath: string;
  modifiedAt: Date;
  title?: string;
}

async function listSessions(limit = 10): Promise<LocalSession[]> {
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
        });
      }
    }

    sessions.sort((a, b) => b.modifiedAt.getTime() - a.modifiedAt.getTime());
    return sessions.slice(0, limit);
  } catch {
    return [];
  }
}

async function getSessionContent(sessionId: string): Promise<string | null> {
  const sessions = await listSessions(100);
  const session = sessions.find(s => s.id === sessionId || s.id.startsWith(sessionId));
  if (!session) return null;
  return await readFile(session.path, 'utf-8');
}

// Simple encryption (matching the CLI)
function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function encrypt(data: string, key: Uint8Array): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoder.encode(data));

  return {
    ciphertext: Buffer.from(encrypted).toString('base64url'),
    iv: Buffer.from(iv).toString('base64url'),
  };
}

async function shareSession(sessionId: string, title?: string): Promise<{ url: string } | { error: string }> {
  const content = await getSessionContent(sessionId);
  if (!content) {
    return { error: `Session not found: ${sessionId}` };
  }

  // Parse session for metadata
  const lines = content.trim().split('\n');
  let messageCount = 0;
  let toolCount = 0;
  let sessionTitle = title || 'Untitled Session';
  const timestamps: number[] = [];

  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      if (parsed.type === 'summary' && parsed.summary && !title) {
        sessionTitle = parsed.summary;
      }
      if (parsed.type === 'user' || parsed.type === 'assistant') {
        messageCount++;
      }
      if (parsed.timestamp) {
        timestamps.push(new Date(parsed.timestamp).getTime());
      }
      if (parsed.message?.content && Array.isArray(parsed.message.content)) {
        toolCount += parsed.message.content.filter((b: any) => b.type === 'tool_use').length;
      }
    } catch {}
  }

  const durationSeconds = timestamps.length >= 2
    ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000)
    : 0;

  // Encrypt
  const key = generateKey();
  const sessionData = JSON.stringify({
    id: sessionId,
    title: sessionTitle,
    messages: [], // We'd need full parsing here - simplified for now
    metadata: { messageCount, toolCount, durationSeconds, startTime: new Date().toISOString(), endTime: new Date().toISOString(), tools: {} }
  });

  const { ciphertext, iv } = await encrypt(content, key);

  // Upload
  try {
    const response = await fetch(`${API_URL}/api/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encryptedBlob: ciphertext,
        iv,
        visibility: 'public',
        metadata: {
          title: sessionTitle.slice(0, 200),
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
      description: 'List available Claude Code sessions. Returns the most recent sessions with their IDs, titles, and project paths.',
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
      description: 'Share a Claude Code session to claudereview.com and get an encrypted shareable URL. The session is end-to-end encrypted.',
      inputSchema: {
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session ID to share (use "last" for the most recent session)',
          },
          title: {
            type: 'string',
            description: 'Custom title for the shared session (optional)',
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

    const formatted = sessions.map((s, i) =>
      `${i + 1}. [${s.id.slice(0, 8)}] ${s.title || 'Untitled'}\n   Project: ${s.projectPath}\n   Modified: ${s.modifiedAt.toLocaleString()}`
    ).join('\n\n');

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

    return {
      content: [{ type: 'text', text: `Session shared successfully!\n\nURL: ${result.url}\n\nThis link is end-to-end encrypted. Only people with this exact URL can view the session.` }],
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
