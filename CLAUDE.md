# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

claudereview - Share Claude Code, Codex CLI, and Gemini CLI sessions for code review with E2E encryption.

## Commands

```bash
# Development
bun run dev          # Start server with hot reload
bun run cli list     # List local Claude Code sessions
bun run cli preview --last  # Preview last session

# Database
bun run db:push      # Push schema to database
bun run db:generate  # Generate migrations
bun run db:studio    # Open Drizzle Studio

# Production
bun run start        # Start production server
```

## Architecture

```
CLI (ccshare)                    Server (Hono)
     │                                │
     ├─ session.ts ──────────────────→│ /api/sessions (upload)
     │   └─ Discovers sessions from:  │
     │      ~/.claude/projects/       │
     │      ~/.codex/sessions/        │
     │      ~/.gemini/tmp/            │
     │                                │
     ├─ parser.ts ────────────────────│
     │   codex-parser.ts              │ /s/:id (viewer page)
     │   gemini-parser.ts             │   └─ Client-side decryption
     │                                │
     ├─ crypto.ts ────────────────────│ /api/sessions/:id (fetch encrypted)
     │   └─ AES-256-GCM encrypt       │
     │                                │
     └─ renderer.ts ──────────────────│ Generates TUI-style HTML
         └─ Self-contained HTML       │
```

**Key modules:**
- **session.ts**: Session discovery and parsing orchestration across all CLI types
- **parser.ts / codex-parser.ts / gemini-parser.ts**: JSONL/JSON parsing for each CLI format
- **crypto.ts**: AES-256-GCM encryption with PBKDF2 key derivation
- **renderer.ts**: Generates self-contained HTML with syntax highlighting and diff views
- **server.ts**: Hono routes for OAuth, session upload/retrieval, and viewer
- **db/schema.ts**: Drizzle ORM schema (users, sessions, apiKeys, sessionViews)

## Session Formats

**Claude Code** (`~/.claude/projects/<project>/*.jsonl`):
```jsonl
{"type":"summary","summary":"Session title..."}
{"type":"user","message":{"role":"user","content":"prompt"},...}
{"type":"assistant","message":{"role":"assistant","content":[...]},...}
```

**Codex CLI** (`~/.codex/sessions/YYYY/MM/DD/*.jsonl`):
```jsonl
{"timestamp":"...","type":"session_meta","payload":{...}}
{"timestamp":"...","type":"response_item","payload":{"type":"message",...}}
```

**Gemini CLI** (`~/.gemini/tmp/<hash>/chats/*.json`):
```json
{"messages":[{"role":"user","parts":[{"text":"..."}]},{"role":"model","parts":[...]}]}
```

## Encryption Flow

1. **Public shares**: Random 256-bit key → AES-256-GCM encrypt → key embedded in URL fragment (`#key=xxx`)
2. **Private shares**: Password → PBKDF2 (100k iterations) → AES key. Salt stored on server.

The `#key=xxx` fragment is never sent to the server. Decryption happens entirely client-side.

## Environment

```bash
DATABASE_PATH=./data/claudereview.db  # SQLite database path (default: ./data/claudereview.db)
BASE_URL=http://192.168.1.100:3000    # Public URL (supports IP addresses for intranet)
SITE_NAME=claudereview                # Site name for branding (default: claudereview)
PORT=3000                             # Server port
GITHUB_CLIENT_ID=...                  # OAuth (optional)
GITHUB_CLIENT_SECRET=...              # OAuth (optional)
CCSHARE_API_KEY=...                   # CLI authentication (optional)
```

## K8s Deployment Notes

SQLite stores data in a local file, so for K8s deployment:
- Use a PersistentVolumeClaim to persist `/app/data`
- Run as single replica (SQLite doesn't support concurrent writes from multiple instances)
- Set `DATABASE_PATH=/app/data/claudereview.db`
