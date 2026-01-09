// Types for Claude Code session parsing and sharing

// Raw JSONL message types from Claude Code sessions
export interface RawMessage {
  type: 'user' | 'assistant' | 'summary' | 'file-history-snapshot';
  uuid?: string;
  parentUuid?: string | null;
  timestamp?: string;
  sessionId?: string;
  message?: {
    role: 'user' | 'assistant';
    content: string | ContentBlock[];
  };
  summary?: string;
  toolUseResult?: {
    stdout?: string;
    stderr?: string;
    isImage?: boolean;
    status?: string;
  };
}

export interface ContentBlock {
  type: 'text' | 'thinking' | 'tool_use' | 'tool_result';
  text?: string;
  thinking?: string;
  name?: string;
  id?: string;
  input?: Record<string, unknown>;
  tool_use_id?: string;
  content?: string | ContentBlock[];
  is_error?: boolean;
}

// Parsed session structure
export interface ParsedSession {
  id: string;
  title: string;
  messages: ParsedMessage[];
  metadata: SessionMetadata;
  source: 'claude' | 'codex' | 'gemini';
}

export interface SessionMetadata {
  messageCount: number;
  toolCount: number;
  durationSeconds: number;
  startTime: string;
  endTime: string;
  tools: Record<string, number>; // tool name -> usage count
  // Key moments for TL;DR
  filesCreated?: string[];
  filesModified?: string[];
  commandsRun?: string[];
  // Estimated usage
  estimatedTokens?: number;
  // Git context if detectable
  gitRepo?: string;
  gitBranch?: string;
  gitCommit?: string;
  // Codex-specific metadata
  model?: string; // e.g., "gpt-5-codex"
  effortLevel?: string; // e.g., "high"
  cliVersion?: string; // e.g., "0.39.0"
  originator?: string; // e.g., "codex_cli_rs"
  // Actual token counts from Codex (vs estimated)
  actualInputTokens?: number;
  actualOutputTokens?: number;
  actualCachedTokens?: number;
}

export interface ParsedMessage {
  id: string;
  type: 'human' | 'assistant' | 'tool_call' | 'tool_result';
  content: string;
  timestamp: string;
  // For tool_call type
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
  // For tool_result type
  toolOutput?: string;
  isError?: boolean;
  // For assistant type with multiple parts
  parts?: MessagePart[];
}

export interface MessagePart {
  type: 'text' | 'tool_call';
  content?: string;
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
}

// Session discovery
export interface LocalSession {
  id: string;
  path: string;
  projectPath: string;
  modifiedAt: Date;
  title?: string;
  source: 'claude' | 'codex' | 'gemini';
}

// Encrypted session for upload
export interface EncryptedSession {
  encryptedBlob: string; // base64 encoded
  iv: string; // base64 encoded initialization vector
  metadata: {
    title: string;
    messageCount: number;
    toolCount: number;
    durationSeconds: number;
  };
  visibility: 'public' | 'private';
  salt?: string; // for private sessions (password key derivation)
}

// API types
export interface UploadRequest {
  encryptedBlob: string;
  iv: string;
  metadata: {
    title: string;
    messageCount: number;
    toolCount: number;
    durationSeconds: number;
  };
  visibility: 'public' | 'private';
  salt?: string;
}

export interface UploadResponse {
  id: string;
  url: string;
  key?: string; // encryption key for public sessions (to construct full URL)
}

export interface SessionResponse {
  id: string;
  encryptedBlob: string;
  iv: string;
  visibility: 'public' | 'private';
  salt?: string;
  metadata: {
    title: string;
    messageCount: number;
    toolCount: number;
    durationSeconds: number;
    createdAt: string;
  };
}

// Codex raw JSONL types
export interface CodexRawLine {
  timestamp: string;
  type: 'session_meta' | 'response_item' | 'event_msg' | 'turn_context';
  payload: CodexPayload;
}

export type CodexPayload =
  | CodexSessionMeta
  | CodexResponseItem
  | CodexEventMsg
  | CodexTurnContext;

export interface CodexSessionMeta {
  id: string;
  timestamp: string;
  cwd: string;
  originator: string;
  cli_version: string;
  instructions: string | null;
  git?: {
    commit_hash?: string;
    branch?: string;
    repository_url?: string;
  };
}

export interface CodexResponseItem {
  type: 'message' | 'function_call' | 'function_call_output' | 'reasoning';
  role?: 'user' | 'assistant';
  content?: Array<{ type: string; text?: string }>;
  name?: string;
  arguments?: string;
  call_id?: string;
  output?: string;
  summary?: Array<{ type: string; text: string }>;
  encrypted_content?: string;
}

export interface CodexEventMsg {
  type: 'agent_reasoning' | 'token_count' | 'agent_message' | 'user_message';
  text?: string;
  message?: string;
  kind?: string;
  info?: {
    total_token_usage: {
      input_tokens: number;
      output_tokens: number;
      cached_input_tokens: number;
      reasoning_output_tokens: number;
      total_tokens: number;
    };
    last_token_usage?: {
      input_tokens: number;
      output_tokens: number;
      cached_input_tokens: number;
      reasoning_output_tokens: number;
      total_tokens: number;
    };
    model_context_window?: number;
  };
}

export interface CodexTurnContext {
  cwd: string;
  approval_policy: string;
  sandbox_policy: {
    mode: string;
    network_access: boolean;
    exclude_tmpdir_env_var: boolean;
    exclude_slash_tmp: boolean;
  };
  model: string;
  effort?: string;
  summary?: string;
}

// Gemini CLI raw JSON types
export interface GeminiSession {
  messages?: GeminiMessage[];
  // Alternative: content array at top level
  contents?: GeminiMessage[];
  // Session metadata (may be at top level or nested)
  sessionId?: string;
  model?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface GeminiMessage {
  role: 'user' | 'model';
  parts: GeminiPart[];
}

export interface GeminiPart {
  text?: string;
  inlineData?: {
    mimeType: string;
    data: string; // base64
  };
  fileData?: {
    mimeType: string;
    fileUri: string;
  };
  functionCall?: {
    name: string;
    args: Record<string, unknown>;
  };
  functionResponse?: {
    id?: string;
    name: string;
    response: {
      output?: string;
      error?: string;
      [key: string]: unknown;
    };
  };
}
