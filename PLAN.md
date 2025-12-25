# Claude Code Session Sharing - Implementation Plan

## Overview
Build **claudereview.com** - a tool to share Claude Code sessions for code review with E2E encryption, user accounts, and a beautiful TUI-style viewer.

## MVP Scope (What We're Building First)
| Feature | Status |
|---------|--------|
| CLI to parse & share sessions | MVP |
| E2E encrypted uploads | MVP |
| Public links (key in URL fragment) | MVP |
| Private links (password-protected) | MVP |
| TUI-style web viewer | MVP |
| GitHub OAuth for user accounts | MVP |
| User dashboard (list/delete sessions) | MVP |
| Deep linking to messages | MVP |
| OG meta tags for link unfurling | MVP |
| Railway deployment | MVP |

## Design Note
Will use the **frontend-design skill** for the landing page, dashboard, and viewer to ensure a beautiful, classy design that avoids generic template aesthetics.

---

## Architecture

### Core Principles
1. **E2E Encryption** - Server stores only encrypted blobs, can't read content
2. **Public links** - Encryption key embedded in URL fragment (never sent to server)
3. **Private links** - Key derived from user password via Argon2
4. **User accounts** - Track sessions you've created, manage links

### Encryption Scheme

```
PUBLIC LINK:
┌─────────┐    ┌─────────────┐    ┌────────────────────────────────┐
│   CLI   │───▶│ Encrypt with│───▶│ Upload encrypted blob + metadata│
│         │    │ random key  │    │ to server                       │
└─────────┘    └─────────────┘    └────────────────────────────────┘
                     │
                     ▼
         URL: claudereview.com/abc123#key=<base64-key>
                                      └── Fragment never sent to server

PRIVATE LINK:
┌─────────┐    ┌─────────────┐    ┌────────────────────────────────┐
│   CLI   │───▶│ Encrypt with│───▶│ Upload encrypted blob + metadata│
│         │    │ password key│    │ to server                       │
└─────────┘    └─────────────┘    └────────────────────────────────┘
                     │
                     ▼
         URL: claudereview.com/abc123 (no key in URL)
         Viewer prompts for password, derives key, decrypts in browser
```

### Tech Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Runtime | Bun | Fast, TypeScript-native, single binary for CLI |
| Web Framework | Hono | Fast, lightweight, works with Bun |
| Database | PostgreSQL (Railway) | Metadata storage, user accounts |
| Blob Storage | Railway Volume or PostgreSQL | Encrypted session blobs |
| Auth | GitHub OAuth | Natural fit for devs, no email setup needed |
| Frontend | Vanilla HTML/CSS/JS | Self-contained, no build step for viewer |
| Encryption | Web Crypto API | Browser-native, AES-256-GCM |
| CLI Encryption | Node crypto | Compatible with Web Crypto |

### Data Model

```sql
-- Users (from GitHub OAuth)
users (
  id TEXT PRIMARY KEY,  -- nanoid
  github_id TEXT UNIQUE,
  github_username TEXT,
  created_at TIMESTAMP
)

-- Sessions (metadata only - content is encrypted)
sessions (
  id TEXT PRIMARY KEY,  -- short nanoid for URLs
  user_id TEXT REFERENCES users,  -- nullable for anonymous
  title TEXT,  -- extracted from first message (truncated)
  message_count INT,
  tool_count INT,
  duration_seconds INT,
  visibility TEXT,  -- 'public' | 'private'
  encrypted_blob BYTEA,  -- the actual encrypted session
  salt TEXT,  -- for private sessions (password key derivation)
  created_at TIMESTAMP,
  expires_at TIMESTAMP  -- optional expiration
)

-- API Keys (for CLI auth)
api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users,
  key_hash TEXT,  -- hashed API key
  name TEXT,
  created_at TIMESTAMP,
  last_used_at TIMESTAMP
)
```

### URL Structure

```
claudereview.com/                     -- Landing page
claudereview.com/login                -- GitHub OAuth
claudereview.com/dashboard            -- User's sessions list
claudereview.com/s/{id}               -- View session (public or private)
claudereview.com/s/{id}#key={base64}  -- View public session (key in fragment)
claudereview.com/s/{id}#msg-{n}       -- Deep link to message
claudereview.com/api/upload           -- CLI upload endpoint
claudereview.com/api/sessions         -- User's sessions list
```

---

## Implementation Phases

### Phase 1: Core MVP
1. **Project Setup**
   - Initialize Bun project in /Users/vignesh/claudereview
   - Add git remote origin
   - Configure TypeScript, ESLint

2. **Session Parser** (`src/parser.ts`)
   - Parse JSONL from ~/.claude/projects/*/
   - Handle message types: user, assistant, summary, file-history-snapshot
   - Extract tool_use blocks from assistant messages
   - Extract tool_result from user messages
   - Build structured session object

3. **Encryption Module** (`src/crypto.ts`)
   - AES-256-GCM encryption/decryption
   - Random key generation for public links
   - Argon2 key derivation for private links
   - Compatible between Node (CLI) and browser

4. **HTML Renderer** (`src/renderer.ts`)
   - TUI-style dark theme
   - Self-contained HTML with embedded CSS/JS
   - Collapsible tool outputs
   - Syntax highlighting (embedded Prism.js)
   - Decryption logic in browser JS

5. **CLI** (`src/cli.ts`)
   - `ccshare list` - list local sessions
   - `ccshare preview <id>` - open in browser locally
   - `ccshare share <id> [--private]` - upload and get URL
   - `ccshare export <id>` - save HTML locally
   - `ccshare auth` - browser OAuth flow

6. **Web Server** (`src/server.ts`)
   - `POST /api/upload` - receive encrypted blob
   - `GET /s/:id` - serve viewer page
   - `GET /api/session/:id` - return encrypted blob as JSON
   - GitHub OAuth endpoints

7. **Database Layer** (`src/db/`)
   - Drizzle ORM setup
   - Schema definition
   - Migration scripts

### Phase 2: Polish
8. **User Dashboard**
   - List created sessions
   - Delete sessions
   - Copy links

9. **Deep Linking & OG Tags**
   - Anchor IDs on messages
   - Open Graph meta tags for unfurling
   - Static OG image

10. **Railway Deployment**
    - Dockerfile / railway.json
    - Environment variables
    - PostgreSQL provisioning

### Phase 3: Enhancements (Post-MVP)
- Session expiration
- View analytics (view count)
- PR/commit linking
- Claude Code slash command installer
- Password change for private sessions

---

## File Structure

```
claudereview/
├── src/
│   ├── cli.ts              # CLI entry point
│   ├── server.ts           # Hono web server
│   ├── parser.ts           # JSONL session parser
│   ├── renderer.ts         # HTML generation
│   ├── crypto.ts           # Encryption utilities
│   ├── session.ts          # Session discovery & management
│   ├── db/
│   │   ├── schema.ts       # Drizzle schema
│   │   ├── index.ts        # Database connection
│   │   └── migrate.ts      # Migration runner
│   ├── routes/
│   │   ├── api.ts          # API routes
│   │   ├── auth.ts         # OAuth routes
│   │   └── viewer.ts       # Session viewer route
│   └── templates/
│       └── viewer.html     # HTML template for viewer
├── package.json
├── tsconfig.json
├── drizzle.config.ts
├── Dockerfile
├── railway.json
└── README.md
```

---

## Key Design Decisions

### 1. Encryption in URL Fragment
The `#key=xxx` fragment is never sent to the server. The browser-side JS extracts it, decrypts the blob fetched from the server. True E2E encryption.

### 2. Metadata Extraction
For the dashboard and OG tags, we need some unencrypted metadata:
- Title (first human message, truncated)
- Message count
- Tool count
- Duration

This is acceptable as it reveals structure but not content.

### 3. Private Session Password
- Use Argon2id for key derivation (memory-hard, resistant to GPU attacks)
- Store salt on server for key derivation
- No password recovery - if lost, session is gone

### 4. Self-Contained Viewer
The HTML viewer includes:
- All CSS inline
- All JS inline (including decryption logic)
- Prism.js for syntax highlighting (minified)
- Session data as encrypted JSON in a script tag

This means exported sessions work offline.

### 5. Bun for Everything
- CLI is a single compiled binary
- Server runs on Bun (fast)
- No separate build step needed
- Native TypeScript support

---

## Open Questions Resolved

| Question | Decision |
|----------|----------|
| Auth method | GitHub OAuth (fits developer audience) |
| CLI auth | Browser OAuth flow (like `gh auth login`) |
| Lost password | Unrecoverable (true E2E) |
| Storage | PostgreSQL for blobs (simplicity over blob storage for v1) |
| Framework | Hono + Bun (performance + simplicity) |

---

## Session Format Reference

From exploration of ~/.claude/projects/:

```jsonl
{"type":"summary","summary":"Session title...","leafUuid":"..."}
{"type":"user","message":{"role":"user","content":"prompt text"},"uuid":"...","timestamp":"...","sessionId":"..."}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"..."},{"type":"text","text":"..."},{"type":"tool_use","name":"Bash","input":{...}}]},"uuid":"...","timestamp":"..."}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"...","content":"output"}]},"uuid":"...","toolUseResult":{"stdout":"...","stderr":"..."}}
```

Key parsing notes:
- `type: "user"` with string content = human message
- `type: "user"` with array content containing `tool_result` = tool output
- `type: "assistant"` content is always an array of blocks
- `type: "thinking"` blocks should be hidden
- `toolUseResult` has parsed stdout/stderr

---

## Next Steps

1. Set up project with Bun and add git remote
2. Implement parser first (core logic)
3. Build renderer with TUI styling
4. Add encryption layer
5. Create CLI commands
6. Build web server
7. Deploy to Railway
