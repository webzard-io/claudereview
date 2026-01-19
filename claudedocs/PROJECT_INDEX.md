# claudereview - Project Index

> Share Claude Code, Codex CLI, and Gemini CLI sessions for code review with E2E encryption.

## Quick Reference

```plaintext
+-----------------+----------------------------------+-------------------------------+
| Component       | Location                         | Purpose                       |
+-----------------+----------------------------------+-------------------------------+
| CLI Entry       | src/cli.ts                       | Command-line interface        |
| Server Entry    | src/server.ts                    | Hono web server               |
| MCP Server      | mcp/server.ts                    | Model Context Protocol server |
| Types           | src/types.ts                     | Shared TypeScript interfaces  |
| Database Schema | src/db/schema.ts                 | Drizzle ORM tables            |
+-----------------+----------------------------------+-------------------------------+
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              claudereview                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  CLI (ccshare)                              Server (Hono)                       │
│  ─────────────                              ─────────────                        │
│       │                                          │                               │
│       ├─ session.ts ────────────────────────────→│ /api/upload                  │
│       │   └─ Discovers sessions from:            │                               │
│       │      ~/.claude/projects/                 │                               │
│       │      ~/.codex/sessions/                  │                               │
│       │      ~/.gemini/tmp/                      │                               │
│       │                                          │                               │
│       ├─ parser.ts ─────────────────────────────→│ /s/:id (viewer)              │
│       │   codex-parser.ts                        │   └─ Client-side decrypt     │
│       │   gemini-parser.ts                       │                               │
│       │                                          │                               │
│       ├─ crypto.ts ─────────────────────────────→│ /api/sessions/:id            │
│       │   └─ AES-256-GCM                         │                               │
│       │                                          │                               │
│       └─ renderer.ts ───────────────────────────→│ Self-contained HTML          │
│           └─ TUI-style viewer                    │                               │
│                                                  │                               │
│  MCP Server                                      │                               │
│  ──────────                                      │                               │
│       │                                          │                               │
│       └─ mcp/server.ts ─────────────────────────→│ /api/upload                  │
│           └─ list_sessions                       │                               │
│           └─ share_session                       │                               │
│           └─ copy_session                        │                               │
│                                                  │                               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Reference

### Core Modules

#### `src/types.ts`
Type definitions for the entire application.

```plaintext
+----------------------+-----------------------------------------------+
| Type                 | Purpose                                       |
+----------------------+-----------------------------------------------+
| RawMessage           | Raw JSONL message from Claude Code            |
| ContentBlock         | Text/tool_use/tool_result content             |
| ParsedSession        | Normalized session structure                  |
| ParsedMessage        | Normalized message (human/assistant/tool)     |
| SessionMetadata      | Stats, timestamps, tools, git context         |
| LocalSession         | Discovered session info                       |
| EncryptedSession     | Session ready for upload                      |
| UploadRequest        | API upload payload                            |
| UploadResponse       | API upload result                             |
| SessionResponse      | API session fetch result                      |
| CodexRawLine         | Codex JSONL line types                        |
| GeminiSession        | Gemini CLI JSON structure                     |
+----------------------+-----------------------------------------------+
```

#### `src/session.ts`
Session discovery and orchestration across all CLI types.

**Key Functions:**
- `listSessions()` - Lists all sessions from Claude/Codex/Gemini
- `listClaudeSessions()` - Scans `~/.claude/projects/`
- `listCodexSessions()` - Scans `~/.codex/sessions/YYYY/MM/DD/`
- `listGeminiSessions()` - Scans `~/.gemini/tmp/*/chats/`
- `getSession(id)` - Find session by ID or index
- `getLastSession()` - Get most recent session
- `parseSession(id)` - Parse session content by ID
- `detectGitContext(path)` - Extract git repo/branch/commit

#### `src/parser.ts`
Claude Code JSONL parser.

**Key Functions:**
- `parseSessionFile(path)` - Parse JSONL file to ParsedSession
- `parseSessionContent(content, id)` - Parse raw JSONL content

**JSONL Format:**
```jsonl
{"type":"summary","summary":"Session title..."}
{"type":"user","message":{"role":"user","content":"prompt"}}
{"type":"assistant","message":{"role":"assistant","content":[...]}}
```

#### `src/codex-parser.ts`
Codex CLI JSONL parser.

**Key Functions:**
- `parseCodexSessionFile(path)` - Parse Codex file
- `parseCodexSessionContent(content, id)` - Parse Codex content
- `isCodexFormat(content)` - Detect Codex format

**Codex JSONL Format:**
```jsonl
{"type":"session_meta","payload":{"cwd":"...","originator":"codex_cli_rs"}}
{"type":"turn_context","payload":{"model":"gpt-5-codex","effort":"high"}}
{"type":"response_item","payload":{"type":"message","role":"user",...}}
{"type":"event_msg","payload":{"type":"token_count","info":{...}}}
```

#### `src/gemini-parser.ts`
Gemini CLI JSON parser.

**Key Functions:**
- `parseGeminiSessionFile(path)` - Parse Gemini file
- `parseGeminiSessionContent(content, id)` - Parse Gemini content
- `isGeminiFormat(content)` - Detect Gemini format

**Gemini JSON Format:**
```json
{
  "messages": [
    {"role": "user", "parts": [{"text": "..."}]},
    {"role": "model", "parts": [{"text": "..."}, {"functionCall": {...}}]}
  ]
}
```

#### `src/crypto.ts`
AES-256-GCM encryption with PBKDF2 key derivation.

**Key Functions:**
- `generateKey()` - Generate random 32-byte key
- `generateSalt()` - Generate random 16-byte salt
- `deriveKey(password, salt)` - PBKDF2 with 600K iterations
- `encrypt(data, key)` - AES-256-GCM encryption
- `decrypt(ciphertext, iv, key)` - AES-256-GCM decryption
- `encryptForPublic(data)` - Encrypt with random key
- `encryptForPrivate(data, password)` - Encrypt with password-derived key

**Browser-Compatible Code:**
`BROWSER_CRYPTO_CODE` - Exported JS for client-side decryption using Web Crypto API.

#### `src/renderer.ts`
TUI-style HTML viewer generator.

**Key Function:**
- `renderSessionToHtml(session, options)` - Generate self-contained HTML

**Features:**
- Dark/light theme toggle
- Search overlay (⌘F)
- Collapsible tool outputs
- Syntax highlighting
- Diff view for Edit operations
- Key moments summary
- Git context display
- Deep linking to messages
- OG meta tags

#### `src/diff.ts`
Line-based diff generation using LCS algorithm.

**Key Function:**
- `diffLines(oldStr, newStr)` - Generate diff with add/remove/unchanged lines

#### `src/text-formatter.ts`
Markdown/text export for clipboard.

**Key Functions:**
- `formatSessionAsMarkdown(session)` - Full Markdown export
- `formatSessionAsPlainText(session)` - Plain text export

---

### Server (`src/server.ts`)

Hono web server with:

**Routes:**

```plaintext
+---------------------------+---------+----------------------------------------+
| Route                     | Method  | Purpose                                |
+---------------------------+---------+----------------------------------------+
| /health                   | GET     | Health check                           |
| /auth/github              | GET     | GitHub OAuth initiation                |
| /auth/github/callback     | GET     | GitHub OAuth callback                  |
| /auth/logout              | GET     | Logout                                 |
| /api/upload               | POST    | Upload encrypted session               |
| /api/sessions/:id         | GET     | Fetch encrypted session                |
| /api/sessions/:id         | PATCH   | Update session title                   |
| /api/sessions/:id         | DELETE  | Delete session                         |
| /api/my-sessions          | GET     | List user's sessions                   |
| /api/keys                 | GET     | List API keys                          |
| /api/keys                 | POST    | Create API key                         |
| /api/keys/:id             | DELETE  | Delete API key                         |
| /s/:id                    | GET     | Session viewer page                    |
| /dashboard                | GET     | User dashboard                         |
| /                         | GET     | Home page                              |
+---------------------------+---------+----------------------------------------+
```

**Authentication:**
- GitHub OAuth for user accounts
- Session cookies (30-day expiry)
- API keys (cr_xxx format) for CLI auth
- Argon2 for API key hashing

---

### Database (`src/db/schema.ts`)

Drizzle ORM schema with PostgreSQL.

**Tables:**

```plaintext
+---------------+----------------------------------------------------------+
| Table         | Columns                                                  |
+---------------+----------------------------------------------------------+
| users         | id, githubId, githubUsername, githubAvatarUrl, createdAt |
| sessions      | id, userId, title, messageCount, toolCount,              |
|               | durationSeconds, visibility, encryptedBlob, iv, salt,    |
|               | ownerKey, viewCount, createdAt, expiresAt                |
| apiKeys       | id, userId, keyHash, name, createdAt, lastUsedAt         |
| sessionViews  | id, sessionId, country, city, latitude, longitude,       |
|               | viewedAt                                                 |
+---------------+----------------------------------------------------------+
```

---

### CLI (`src/cli.ts`)

Commander-based CLI with commands:

```plaintext
+-------------+--------------------------+------------------------------------+
| Command     | Options                  | Description                        |
+-------------+--------------------------+------------------------------------+
| list        | -n, --limit              | List sessions                      |
|             | -p, --project            | Filter by project                  |
+-------------+--------------------------+------------------------------------+
| preview     | -l, --last               | Preview in browser                 |
| [session-id]| -t, --title              |                                    |
|             | --light, --embed         |                                    |
+-------------+--------------------------+------------------------------------+
| export      | -l, --last               | Export to HTML file                |
| [session-id]| -o, --output             |                                    |
|             | -t, --title              |                                    |
|             | --light, --embed         |                                    |
|             | --private <password>     |                                    |
+-------------+--------------------------+------------------------------------+
| share       | -l, --last               | Upload and get URL                 |
| [session-id]| -t, --title              |                                    |
|             | --private <password>     |                                    |
|             | -q, --quiet              |                                    |
+-------------+--------------------------+------------------------------------+
| copy        | -l, --last               | Copy as Markdown                   |
| [session-id]| -o, --output             |                                    |
|             | --stdout, --plain        |                                    |
+-------------+--------------------------+------------------------------------+
| auth        | --status, --logout       | GitHub authentication              |
+-------------+--------------------------+------------------------------------+
```

---

### MCP Server (`mcp/server.ts`)

Model Context Protocol server for IDE integration.

**Tools:**

```plaintext
+---------------+-------------------------------+-------------------------------+
| Tool          | Parameters                    | Description                   |
+---------------+-------------------------------+-------------------------------+
| list_sessions | limit?: number                | List available sessions       |
| share_session | session_id: string            | Share session, get URL        |
|               | title?: string                |                               |
| copy_session  | session_id: string            | Copy as Markdown              |
+---------------+-------------------------------+-------------------------------+
```

**Configuration (~/.mcp.json):**
```json
{
  "mcpServers": {
    "claudereview": {
      "command": "bunx",
      "args": ["smartx-claudereview-mcp"],
      "env": { "CCSHARE_API_KEY": "your-key" }
    }
  }
}
```

---

## Security Model

### Public Sessions
1. CLI generates random AES-256-GCM key
2. Session encrypted client-side
3. Encrypted blob uploaded to server
4. Key embedded in URL fragment: `#key=xxx`
5. Fragment never sent to server
6. Browser decrypts using Web Crypto API

### Private Sessions
1. User provides password
2. PBKDF2 derives key (600K iterations, SHA-256)
3. Salt stored on server
4. URL contains no key: viewer prompts for password
5. Browser derives key and decrypts

---

## Session Storage Locations

```plaintext
+-------------+-----------------------------------------------+---------------+
| CLI         | Location                                      | Format        |
+-------------+-----------------------------------------------+---------------+
| Claude Code | ~/.claude/projects/<encoded-path>/<uuid>.jsonl| JSONL         |
| Codex CLI   | ~/.codex/sessions/YYYY/MM/DD/<timestamp>.jsonl| JSONL         |
| Gemini CLI  | ~/.gemini/tmp/<project-hash>/chats/*.json     | JSON          |
+-------------+-----------------------------------------------+---------------+
```

---

## Dependencies

```plaintext
+-------------------+---------+------------------------------------------+
| Package           | Version | Purpose                                  |
+-------------------+---------+------------------------------------------+
| hono              | ^4.11   | Web framework                            |
| drizzle-orm       | ^0.45   | Database ORM                             |
| commander         | ^14.0   | CLI framework                            |
| nanoid            | ^5.1    | ID generation                            |
| argon2            | ^0.44   | Password hashing                         |
| zod               | ^4.2    | Schema validation                        |
| sharp             | ^0.34   | Image processing                         |
+-------------------+---------+------------------------------------------+
```

---

## Environment Variables

```plaintext
+----------------------+------------------------------------------+--------------------------+
| Variable             | Description                              | Default                  |
+----------------------+------------------------------------------+--------------------------+
| DATABASE_PATH        | SQLite database path                     | ./data/claudereview.db   |
| BASE_URL             | Public URL                               | http://localhost:3000    |
| SITE_NAME            | Site name for branding                   | claudereview             |
| PORT                 | Server port                              | 3000                     |
| GITHUB_CLIENT_ID     | GitHub OAuth app ID                      | (required for auth)      |
| GITHUB_CLIENT_SECRET | GitHub OAuth secret                      | (required for auth)      |
| SESSION_SECRET       | Cookie signing secret                    | dev-secret               |
| CCSHARE_API_URL      | API URL for CLI                          | http://192.168.17.244:31935 |
| CCSHARE_API_KEY      | API key for authenticated uploads        | (optional)               |
| ALLOW_INSECURE_DECRYPTION | Enable server-side decryption fallback (HTTP) | false                |
+----------------------+------------------------------------------+--------------------------+
```

---

## Development Commands

```bash
# Development
bun run dev              # Start server with hot reload
bun run cli list         # List local sessions
bun run cli preview --last  # Preview last session

# Database
bun run db:studio        # Open Drizzle Studio

# Production
bun run start            # Start production server
```

---

## File Tree

```
claudereview/
├── src/
│   ├── cli.ts              # CLI entry point
│   ├── server.ts           # Hono web server
│   ├── types.ts            # Shared types
│   ├── session.ts          # Session discovery
│   ├── parser.ts           # Claude JSONL parser
│   ├── codex-parser.ts     # Codex JSONL parser
│   ├── gemini-parser.ts    # Gemini JSON parser
│   ├── crypto.ts           # AES-256-GCM encryption
│   ├── constants.ts        # Env-backed defaults and branding
│   ├── renderer.ts         # HTML viewer generator
│   ├── diff.ts             # Line-based diff
│   ├── text-formatter.ts   # Markdown/text export
│   └── db/
│       ├── index.ts        # Database connection
│       └── schema.ts       # Drizzle schema
├── mcp/
│   ├── server.ts           # MCP server
│   ├── renderer.ts         # MCP renderer copy
│   ├── diff.ts             # MCP diff copy
│   └── types.ts            # MCP types copy
├── plugin/
│   ├── commands/share.md   # Slash command
│   └── skills/share-session/SKILL.md
├── package.json
├── tsconfig.json
├── drizzle.config.ts
├── CLAUDE.md
└── README.md
```

---

*Generated by /sc:index on 2026-01-18*
