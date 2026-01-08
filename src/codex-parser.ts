import { readFile } from 'fs/promises';
import type {
  ParsedSession,
  ParsedMessage,
  SessionMetadata,
  CodexRawLine,
  CodexSessionMeta,
  CodexResponseItem,
  CodexEventMsg,
  CodexTurnContext,
} from './types.ts';

/**
 * Parse a Codex session JSONL file into a structured format
 */
export async function parseCodexSessionFile(filePath: string): Promise<ParsedSession> {
  const content = await readFile(filePath, 'utf-8');
  return parseCodexSessionContent(content, extractCodexSessionId(filePath));
}

/**
 * Parse Codex JSONL content directly
 */
export function parseCodexSessionContent(content: string, sessionId: string): ParsedSession {
  const lines = content.trim().split('\n').filter(line => line.trim());
  const messages: ParsedMessage[] = [];
  let sessionMeta: CodexSessionMeta | null = null;
  let latestTurnContext: CodexTurnContext | null = null;
  let messageIndex = 0;

  // Token tracking from event_msg
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalCachedTokens = 0;

  // Key moments tracking
  const filesCreated = new Set<string>();
  const filesModified = new Set<string>();
  const commandsRun: string[] = [];
  const toolCounts: Record<string, number> = {};
  const timestamps: number[] = [];

  // Token estimation fallback
  let totalChars = 0;

  for (const line of lines) {
    try {
      const raw = JSON.parse(line) as CodexRawLine;

      if (raw.timestamp) {
        const ts = new Date(raw.timestamp).getTime();
        if (!isNaN(ts)) {
          timestamps.push(ts);
        }
      }

      switch (raw.type) {
        case 'session_meta':
          sessionMeta = raw.payload as CodexSessionMeta;
          break;

        case 'turn_context':
          latestTurnContext = raw.payload as CodexTurnContext;
          break;

        case 'event_msg': {
          const eventMsg = raw.payload as CodexEventMsg;
          if (eventMsg.type === 'token_count' && eventMsg.info?.total_token_usage) {
            totalInputTokens = eventMsg.info.total_token_usage.input_tokens;
            totalOutputTokens = eventMsg.info.total_token_usage.output_tokens;
            totalCachedTokens = eventMsg.info.total_token_usage.cached_input_tokens;
          }
          break;
        }

        case 'response_item': {
          const item = raw.payload as CodexResponseItem;

          if (item.type === 'message') {
            if (item.role === 'user') {
              // Extract actual user text (skip environment_context)
              const userText = item.content
                ?.filter(c => c.type === 'input_text' && !c.text?.includes('<environment_context>'))
                .map(c => c.text)
                .join('\n');

              if (userText && userText.trim()) {
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
                ?.filter(c => c.type === 'output_text')
                .map(c => c.text)
                .join('\n');

              if (assistantText && assistantText.trim()) {
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
            // Map Codex tool names to Claude Code equivalents
            const toolName = mapCodexToolName(item.name);
            const toolInput = parseCodexToolInput(item.name, item.arguments);

            toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;

            // Track key moments
            if (toolName === 'Bash' && toolInput?.command) {
              const cmd = String(toolInput.command);
              totalChars += cmd.length;
              // Only track interesting commands (not cd, ls, etc.)
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
          break;
        }
      }
    } catch (e) {
      // Skip malformed lines
      console.warn('Skipping malformed Codex line:', e);
    }
  }

  // Compute title from first human message
  let title = 'Untitled Codex Session';
  const firstHuman = messages.find(m => m.type === 'human');
  if (firstHuman) {
    title = truncate(firstHuman.content, 100);
  }

  // Compute timestamps
  const startTime = timestamps.length > 0
    ? new Date(Math.min(...timestamps)).toISOString()
    : new Date().toISOString();
  const endTime = timestamps.length > 0
    ? new Date(Math.max(...timestamps)).toISOString()
    : new Date().toISOString();
  const durationSeconds = timestamps.length >= 2
    ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000)
    : 0;

  const metadata: SessionMetadata = {
    messageCount: messages.filter(m => m.type === 'human' || m.type === 'assistant').length,
    toolCount: Object.values(toolCounts).reduce((a, b) => a + b, 0),
    durationSeconds,
    startTime,
    endTime,
    tools: toolCounts,
    filesCreated: [...filesCreated].slice(0, 20),
    filesModified: [...filesModified].slice(0, 20),
    commandsRun: commandsRun.slice(0, 15),
    // Use actual tokens if available, otherwise estimate
    estimatedTokens: totalInputTokens + totalOutputTokens || Math.round(totalChars / 4),
    // Codex-specific metadata
    model: latestTurnContext?.model,
    effortLevel: latestTurnContext?.effort,
    cliVersion: sessionMeta?.cli_version,
    originator: sessionMeta?.originator,
    actualInputTokens: totalInputTokens || undefined,
    actualOutputTokens: totalOutputTokens || undefined,
    actualCachedTokens: totalCachedTokens || undefined,
    // Git from session_meta
    gitRepo: sessionMeta?.git?.repository_url,
    gitBranch: sessionMeta?.git?.branch,
    gitCommit: sessionMeta?.git?.commit_hash,
  };

  return {
    id: sessionId,
    title,
    messages,
    metadata,
    source: 'codex' as const,
  };
}

/**
 * Map Codex tool names to Claude Code equivalents
 */
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

/**
 * Parse Codex tool arguments (JSON string) into object
 */
function parseCodexToolInput(toolName: string, argsJson?: string): Record<string, unknown> | undefined {
  if (!argsJson) return undefined;

  try {
    const args = JSON.parse(argsJson);

    // Transform shell command array to string
    if (toolName === 'shell' && Array.isArray(args.command)) {
      const cmdArray = args.command as string[];
      // ["bash", "-lc", "actual command"] -> "actual command"
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

/**
 * Format a tool call for display
 */
function formatToolCall(name: string, input?: Record<string, unknown>): string {
  if (!input) return name;

  if (name === 'Bash' && input.command) {
    return `$ ${input.command}`;
  }
  if (name === 'Read' && input.file_path) {
    return `read ${input.file_path}`;
  }
  if (name === 'Write' && input.file_path) {
    return `write ${input.file_path}`;
  }
  if (name === 'Edit' && input.file_path) {
    return `edit ${input.file_path}`;
  }
  if (name === 'Glob' && input.pattern) {
    return `glob ${input.pattern}`;
  }
  if (name === 'Grep' && input.pattern) {
    return `grep ${input.pattern}`;
  }

  return `${name}: ${JSON.stringify(input)}`;
}

/**
 * Extract session ID from Codex file path
 * Filename pattern: rollout-YYYY-MM-DDTHH-MM-SS-{uuid}.jsonl
 */
function extractCodexSessionId(filePath: string): string {
  const match = filePath.match(/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.jsonl$/i);
  return match?.[1] ?? filePath.split('/').pop()?.replace('.jsonl', '') ?? 'unknown';
}

/**
 * Truncate string to max length with ellipsis
 */
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * Detect if content is Codex format
 */
export function isCodexFormat(content: string): boolean {
  const firstLine = content.split('\n')[0];
  if (!firstLine) return false;

  try {
    const parsed = JSON.parse(firstLine);
    return parsed.type === 'session_meta' && parsed.payload?.originator?.includes('codex');
  } catch {
    return false;
  }
}
