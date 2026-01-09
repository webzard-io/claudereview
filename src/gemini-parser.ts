import { readFile } from 'fs/promises';
import type {
  ParsedSession,
  ParsedMessage,
  SessionMetadata,
  GeminiSession,
  GeminiMessage,
  GeminiPart,
} from './types.ts';

/**
 * Parse a Gemini CLI session JSON file into a structured format
 */
export async function parseGeminiSessionFile(filePath: string): Promise<ParsedSession> {
  const content = await readFile(filePath, 'utf-8');
  return parseGeminiSessionContent(content, extractGeminiSessionId(filePath));
}

/**
 * Parse Gemini JSON content directly
 */
export function parseGeminiSessionContent(content: string, sessionId: string): ParsedSession {
  const session = JSON.parse(content) as GeminiSession;
  const messages: ParsedMessage[] = [];
  let messageIndex = 0;

  // Gemini uses either 'messages' or 'contents' array
  const rawMessages = session.messages || session.contents || [];

  // Key moments tracking
  const filesCreated = new Set<string>();
  const filesModified = new Set<string>();
  const commandsRun: string[] = [];
  const toolCounts: Record<string, number> = {};

  // Token estimation
  let totalChars = 0;

  // Track tool calls waiting for results (by function name, since Gemini pairs by order)
  const pendingToolCalls: Map<string, { toolId: string; toolName: string }> = new Map();

  for (const msg of rawMessages) {
    if (msg.role === 'user') {
      // Check if this is a function response (tool result)
      const funcResponses = msg.parts.filter(p => p.functionResponse);
      if (funcResponses.length > 0) {
        // Handle function responses (tool results)
        for (const part of funcResponses) {
          if (part.functionResponse) {
            const funcName = part.functionResponse.name;
            const toolName = mapGeminiToolName(funcName);
            const output = extractFunctionOutput(part.functionResponse.response);
            const isError = !!part.functionResponse.response?.error;

            totalChars += output.length;

            // Use the id from the response, or generate one
            const toolId = part.functionResponse.id || `${funcName}-${messageIndex}`;

            messages.push({
              id: `msg-${messageIndex++}`,
              type: 'tool_result',
              content: output,
              timestamp: session.updatedAt || new Date().toISOString(),
              toolId,
              toolOutput: output,
              isError,
            });
          }
        }
      } else {
        // Regular user message
        const userText = extractTextFromParts(msg.parts);
        if (userText.trim()) {
          totalChars += userText.length;
          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'human',
            content: userText.trim(),
            timestamp: session.updatedAt || new Date().toISOString(),
          });
        }
      }
    } else if (msg.role === 'model') {
      // Handle model response - may contain text and/or function calls
      const textParts = msg.parts.filter(p => p.text);
      const funcCallParts = msg.parts.filter(p => p.functionCall);

      // Add text content first
      if (textParts.length > 0) {
        const assistantText = textParts.map(p => p.text).join('\n');
        if (assistantText.trim()) {
          totalChars += assistantText.length;
          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'assistant',
            content: assistantText.trim(),
            timestamp: session.updatedAt || new Date().toISOString(),
          });
        }
      }

      // Add function calls (tool uses)
      for (const part of funcCallParts) {
        if (part.functionCall) {
          const toolName = mapGeminiToolName(part.functionCall.name);
          const toolInput = part.functionCall.args;
          const toolId = `${part.functionCall.name}-${messageIndex}`;

          toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;

          // Track key moments
          trackKeyMoments(toolName, toolInput, commandsRun, filesCreated, filesModified);

          totalChars += JSON.stringify(toolInput).length;

          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'tool_call',
            content: formatToolCall(toolName, toolInput),
            timestamp: session.updatedAt || new Date().toISOString(),
            toolName,
            toolInput,
            toolId,
          });

          // Store for pairing with result
          pendingToolCalls.set(part.functionCall.name, { toolId, toolName });
        }
      }
    }
  }

  // Compute title from first human message
  let title = 'Untitled Gemini Session';
  const firstHuman = messages.find(m => m.type === 'human');
  if (firstHuman) {
    title = truncate(firstHuman.content, 100);
  }

  const now = new Date().toISOString();
  const metadata: SessionMetadata = {
    messageCount: messages.filter(m => m.type === 'human' || m.type === 'assistant').length,
    toolCount: Object.values(toolCounts).reduce((a, b) => a + b, 0),
    durationSeconds: 0, // Gemini JSON doesn't have timestamps per message
    startTime: session.createdAt || now,
    endTime: session.updatedAt || now,
    tools: toolCounts,
    filesCreated: [...filesCreated].slice(0, 20),
    filesModified: [...filesModified].slice(0, 20),
    commandsRun: commandsRun.slice(0, 15),
    estimatedTokens: Math.round(totalChars / 4),
    model: session.model,
  };

  return {
    id: sessionId,
    title,
    messages,
    metadata,
    source: 'gemini' as const,
  };
}

/**
 * Map Gemini tool names to standardized equivalents
 */
function mapGeminiToolName(geminiName: string): string {
  const mapping: Record<string, string> = {
    // Common Gemini CLI tool names
    'shell': 'Bash',
    'Bash': 'Bash',
    'run_shell_command': 'Bash',
    'execute_command': 'Bash',
    'read_file': 'Read',
    'ReadFile': 'Read',
    'read_file_content': 'Read',
    'write_file': 'Write',
    'WriteFile': 'Write',
    'write_file_content': 'Write',
    'edit_file': 'Edit',
    'EditFile': 'Edit',
    'search_file_content': 'Grep',
    'search_files': 'Grep',
    'list_files': 'LS',
    'list_directory': 'LS',
    'glob': 'Glob',
    'find_files': 'Glob',
  };
  return mapping[geminiName] || geminiName;
}

/**
 * Extract text output from a function response
 */
function extractFunctionOutput(response: Record<string, unknown>): string {
  if (response.output && typeof response.output === 'string') {
    return response.output;
  }
  if (response.error && typeof response.error === 'string') {
    return `Error: ${response.error}`;
  }
  if (response.result && typeof response.result === 'string') {
    return response.result;
  }
  // Fallback: stringify the whole response
  return JSON.stringify(response, null, 2);
}

/**
 * Extract text from message parts
 */
function extractTextFromParts(parts: GeminiPart[]): string {
  return parts
    .filter(p => p.text)
    .map(p => p.text)
    .join('\n');
}

/**
 * Track key moments (files, commands) for session summary
 */
function trackKeyMoments(
  toolName: string,
  toolInput: Record<string, unknown>,
  commandsRun: string[],
  filesCreated: Set<string>,
  filesModified: Set<string>
): void {
  if (toolName === 'Bash') {
    const cmd = String(toolInput?.command || toolInput?.cmd || '');
    if (cmd && !cmd.match(/^(cd|ls|pwd|echo|cat|head|tail)\b/) && cmd.length < 100) {
      commandsRun.push(cmd);
    }
  }
  if (toolName === 'Write') {
    const path = String(toolInput?.file_path || toolInput?.path || toolInput?.filename || '');
    if (path) filesCreated.add(path);
  }
  if (toolName === 'Edit') {
    const path = String(toolInput?.file_path || toolInput?.path || toolInput?.filename || '');
    if (path) filesModified.add(path);
  }
  if (toolName === 'Read') {
    const path = String(toolInput?.file_path || toolInput?.path || toolInput?.filename || '');
    if (path) filesModified.add(path); // Track reads as "touched" files
  }
}

/**
 * Format a tool call for display
 */
function formatToolCall(name: string, input?: Record<string, unknown>): string {
  if (!input) return name;

  const cmd = input.command || input.cmd;
  if (name === 'Bash' && cmd) {
    return `$ ${cmd}`;
  }

  const path = input.file_path || input.path || input.filename;
  if (name === 'Read' && path) {
    return `read ${path}`;
  }
  if (name === 'Write' && path) {
    return `write ${path}`;
  }
  if (name === 'Edit' && path) {
    return `edit ${path}`;
  }

  const pattern = input.pattern || input.query;
  if (name === 'Glob' && pattern) {
    return `glob ${pattern}`;
  }
  if (name === 'Grep' && pattern) {
    return `grep ${pattern}`;
  }

  return `${name}: ${JSON.stringify(input)}`;
}

/**
 * Extract session ID from Gemini file path
 * Filename patterns: session-*.json, checkpoint-*.json
 */
function extractGeminiSessionId(filePath: string): string {
  const filename = filePath.split('/').pop() || '';
  // Remove .json extension and common prefixes
  const id = filename
    .replace('.json', '')
    .replace(/^(session-|checkpoint-)/, '');
  return id || 'unknown';
}

/**
 * Truncate string to max length with ellipsis
 */
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * Detect if content is Gemini JSON format
 */
export function isGeminiFormat(content: string): boolean {
  try {
    const parsed = JSON.parse(content);
    // Gemini sessions have messages/contents array with role/parts structure
    const messages = parsed.messages || parsed.contents;
    if (!Array.isArray(messages) || messages.length === 0) return false;

    // Check first message has role and parts
    const first = messages[0];
    return (
      (first.role === 'user' || first.role === 'model') &&
      Array.isArray(first.parts)
    );
  } catch {
    return false;
  }
}
