# claudereview

Share Claude Code sessions for code review with E2E encryption.

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

- **CLI** (`src/cli.ts`): Parses local sessions, encrypts, and uploads
- **Server** (`src/server.ts`): Hono web server for uploads and viewer
- **Parser** (`src/parser.ts`): Parses Claude Code JSONL sessions
- **Renderer** (`src/renderer.ts`): Generates TUI-style HTML viewer
- **Crypto** (`src/crypto.ts`): AES-256-GCM encryption + Argon2 key derivation

## Session Format

Claude Code stores sessions in `~/.claude/projects/<project>/` as JSONL:

```jsonl
{"type":"summary","summary":"Session title..."}
{"type":"user","message":{"role":"user","content":"prompt"},...}
{"type":"assistant","message":{"role":"assistant","content":[...]},...}
```

## Encryption

- **Public**: Random key, embedded in URL fragment (`#key=xxx`)
- **Private**: Password → Argon2 → AES key. Salt stored on server.

The URL fragment is never sent to the server, ensuring true E2E encryption.

## Tech Stack

- Bun (runtime)
- Hono (web framework)
- Drizzle (ORM)
- PostgreSQL (database)
- Argon2 (key derivation)

## Environment

```bash
DATABASE_URL=postgresql://...
BASE_URL=https://claudereview.com
PORT=3000
```
