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
bun run db:push      # Push schema to database (fast iteration, no migration files)
bun run db:generate  # Generate migrations from schema changes
bun run db:studio    # Open Drizzle Studio
bun run db:migrate   # Run migrations manually

# Production
bun run start        # Start production server
```

## Architecture

```
CLI (ccshare)                    Server (Hono)
     │                                │
     ├─ session.ts ──────────────────→│ POST /api/upload (upload session)
     │   └─ Discovers sessions from:  │
     │      ~/.claude/projects/       │
     │      ~/.codex/sessions/        │
     │      ~/.gemini/tmp/            │
     │                                │
     ├─ parser.ts ────────────────────│ GET  /s/:id (viewer page)
     │   codex-parser.ts              │   └─ Client-side decryption
     │   gemini-parser.ts             │
     │                                │ GET  /api/session/:id (fetch encrypted)
     ├─ crypto.ts ────────────────────│ GET  /api/session/:id/raw (public JSON)
     │   └─ AES-256-GCM encrypt       │ POST /api/session/:id/decrypt (insecure fallback)
     │                                │
     ├─ renderer.ts ──────────────────│ PATCH /api/sessions/:id (edit)
     │   └─ Self-contained HTML       │ DELETE /api/sessions/:id (delete)
     │                                │
     ├─ diff.ts ──────────────────────│ GET  /api/my-sessions (dashboard)
     │   └─ Unified diff rendering    │ POST /api/keys (create API key)
     │                                │ POST /api/feedback (submit feedback)
     └─ text-formatter.ts ───────────│
         └─ Markdown/text formatting  │ GET  /api/admin/stats (admin analytics)
                                      │ POST /api/admin/refresh-sessions
                                      │
                                      │ GET  / (landing page)
                                      │ GET  /dashboard (user dashboard)
                                      │ GET  /admin (admin dashboard)
                                      │ GET  /privacy (privacy page)
                                      │ GET  /health (health check)
```

**Key modules:**
- **session.ts**: Session discovery and parsing orchestration across all CLI types
- **parser.ts / codex-parser.ts / gemini-parser.ts**: JSONL/JSON parsing for each CLI format
- **crypto.ts**: AES-256-GCM encryption with PBKDF2 key derivation (600k iterations)
- **renderer.ts**: Generates self-contained HTML with syntax highlighting and diff views
- **diff.ts**: Unified diff rendering for file edit tool results
- **text-formatter.ts**: Markdown and text formatting utilities
- **constants.ts**: Shared constants (BASE_URL, SITE_NAME, API_URL)
- **types.ts**: TypeScript type definitions (ParsedSession, ParsedMessage, etc.)
- **server.ts**: Hono routes for OAuth, session CRUD, admin, viewer, and static pages
- **db/schema.ts**: Drizzle ORM schema (users, sessions, apiKeys, sessionViews)
- **db/index.ts**: Database initialization with SQLite WAL mode and auto-migration

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

1. **Public shares**: Random 256-bit key → AES-256-GCM encrypt → key embedded in URL fragment (`#key=xxx`). Server stores `ownerKey` for authenticated users (enables dashboard viewing) and `rawJson` (enables `/raw` endpoint).
2. **Private shares**: Password → PBKDF2 (600k iterations, SHA-256) → AES key. Salt stored on server. No `ownerKey` or `rawJson` stored. Switching to private clears `rawJson`.

The `#key=xxx` fragment is never sent to the server. Decryption happens entirely client-side. For HTTP/intranet deployments, an optional server-side decrypt fallback exists (`ALLOW_INSECURE_DECRYPTION=true`).

## Environment

```bash
# Core
DATABASE_PATH=./data/claudereview.db  # SQLite database path (default: ./data/claudereview.db)
BASE_URL=http://192.168.1.100:3000    # Public URL (supports IP addresses for intranet)
SITE_NAME=claudereview                # Site name for branding (default: claudereview)
PORT=3000                             # Server port

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=...                  # OAuth app client ID
GITHUB_CLIENT_SECRET=...              # OAuth app client secret
GITHUB_TOKEN=...                      # For creating feedback issues on GitHub

# Authentication
SESSION_SECRET=...                    # Session signing secret (default: dev-secret-change-in-production)
CCSHARE_API_KEY=...                   # CLI authentication key (client-side)
CCSHARE_API_URL=...                   # CLI API endpoint (default: http://192.168.17.244:31935)
ADMIN_KEY=...                         # Admin dashboard authentication key

# Security
ALLOW_INSECURE_DECRYPTION=false       # Enable server-side decryption fallback for HTTP/intranet (sends key to server)
```

## K8s Deployment Notes

SQLite stores data in a local file, so for K8s deployment:
- Use a PersistentVolumeClaim to persist `/app/data`
- Run as single replica (SQLite doesn't support concurrent writes from multiple instances)
- Set `DATABASE_PATH=/app/data/claudereview.db`
