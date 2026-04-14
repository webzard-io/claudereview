# claudereview

Share Claude Code, Codex CLI, and Gemini CLI sessions for code review. Encrypted.

## Installation

```bash
# Install globally
bun add -g smartx-claudereview

# Or run directly
bunx smartx-claudereview
```

## Usage

```bash
# List your Claude Code, Codex, and Gemini sessions
ccshare list

# Share a specific session by ID
ccshare share abc123

# Share your last session
ccshare share --last

# Share with password protection
ccshare share --last --private "your-password"

# Copy session to clipboard as Markdown
ccshare copy --last

# Copy to stdout instead
ccshare copy --last --stdout

# Copy as plain text (no Markdown formatting)
ccshare copy --last --plain

# Preview the most recent session in browser
ccshare preview --last

# Export to HTML file
ccshare export --last -o session.html

# Export with password protection
ccshare export --last --private "secret" -o session.html

# Authenticate with your API key
ccshare auth

# Check authentication status
ccshare auth --status

# Remove saved credentials
ccshare auth --logout
```

## Features

### Security
- **E2E Encrypted**: Sessions encrypted before upload with AES-256-GCM
- **Key in URL Fragment**: Encryption key never sent to server (`#key=xxx`)
- **Password Protection**: PBKDF2 key derivation (600k iterations, SHA-256) for private shares
- **HTTP Fallback**: Optional server-side decryption for intranet deployments without HTTPS

### Viewer
- **TUI Aesthetic**: Beautiful terminal-style dark/light theme
- **Search**: Full-text search with ⌘F
- **Collapsible Outputs**: Expand/collapse tool results
- **Syntax Highlighting**: Code blocks with language detection
- **Diff View**: Visual unified diffs for file edits
- **Image Support**: Inline display of images from sessions
- **Key Moments**: Summary of files created/modified, commands run
- **Git Context**: Links to repo, branch, and commit
- **Deep Linking**: Link directly to specific messages
- **Token Estimates**: Rough usage statistics

### Export
- **Self-Contained HTML**: Exported files work offline
- **OG Meta Tags**: Rich previews when sharing links
- **Clipboard Copy**: Copy as formatted Markdown or plain text for pasting anywhere

### Dashboard
- **Session Management**: View, edit, delete your shared sessions
- **Visibility Toggle**: Switch sessions between public and private (with re-encryption)
- **API Key Management**: Generate and revoke CLI API keys
- **View Counts**: Track how many times each session has been viewed

### Admin
- **Analytics Dashboard**: Sessions, views, users stats with time period filters
- **Charts**: Sessions per day and views per day over last 30 days
- **Top Viewed**: See most popular sessions
- **Batch Refresh**: Re-render all sessions with the latest renderer

### Multi-CLI Support
- **Claude Code**: Sessions from `~/.claude/projects/`
- **Codex CLI**: Sessions from `~/.codex/sessions/`
- **Gemini CLI**: Sessions from `~/.gemini/tmp/*/chats/`
- **Auto-Detection**: Automatically detects and parses all formats
- **Source Badges**: Shows `[Claude]`, `[Codex]`, or `[Gemini]` in session list

## MCP Integration

### MCP Server

Share sessions directly from Claude Code, Codex, or Gemini CLI by adding to `~/.mcp.json`:

```json
{
  "mcpServers": {
    "claudereview": {
      "command": "bunx",
      "args": ["smartx-claudereview-mcp"],
      "env": {
        "CCSHARE_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Get your API key from [claudereview.com/dashboard](https://claudereview.com/dashboard) after logging in with GitHub.

Then just ask: "Share this session", "List my recent sessions", or "Copy this session as text".

### Slash Command (Claude Code)

Add a quick slash command by creating `~/.claude/commands/share.md`:

```markdown
Share this session using claudereview.

Run: bunx smartx-claudereview share --last

Return the URL to me.
```

Then type `/share` in any session.

> **Note**: Codex CLI and Gemini CLI don't support slash commands. Use the MCP server instead.

## How It Works

### Public Shares
1. CLI encrypts session with a random 256-bit key (AES-256-GCM)
2. Uploads encrypted blob + ownerKey (for authenticated users) + rawJson to server
3. Returns URL with key in fragment: `claudereview.com/s/abc123#key=xxx`
4. The `#key=xxx` fragment is never sent to the server
5. Browser decrypts client-side using Web Crypto API
6. Authenticated users can view their sessions from the dashboard (ownerKey stored server-side)
7. Public sessions also expose a `/api/session/:id/raw` JSON endpoint

### Private Shares
1. CLI derives key from password using PBKDF2 (600k iterations, SHA-256)
2. Encrypts session with derived key (AES-256-GCM), uploads encrypted blob + salt
3. Returns URL without key: `claudereview.com/s/abc123`
4. Viewer prompts for password, derives key client-side, decrypts
5. No ownerKey or rawJson stored — server cannot decrypt

### HTTP/Intranet Fallback
When `ALLOW_INSECURE_DECRYPTION=true`, the viewer falls back to server-side decryption via `POST /api/session/:id/decrypt` if Web Crypto API is unavailable (non-HTTPS contexts). This sends the key/password to the server and is disabled by default.

## Development

```bash
# Install dependencies
bun install

# Run server locally
bun run dev

# Run CLI
bun run cli list
```

## Environment Variables

### Core
- `DATABASE_PATH`: SQLite database path (default: `./data/claudereview.db`)
- `BASE_URL`: Public URL for the server (default: `http://localhost:3000`)
- `SITE_NAME`: Site name for branding (default: `claudereview`)
- `PORT`: Server port (default: `3000`)

### GitHub OAuth (optional)
- `GITHUB_CLIENT_ID`: OAuth app client ID
- `GITHUB_CLIENT_SECRET`: OAuth app client secret
- `GITHUB_TOKEN`: Personal access token for creating feedback issues on GitHub

### Authentication
- `SESSION_SECRET`: Session signing secret (default: `dev-secret-change-in-production`)
- `CCSHARE_API_KEY`: API key for authenticated CLI uploads (client-side)
- `CCSHARE_API_URL`: API endpoint for CLI (default: `http://192.168.17.244:31935`)
- `ADMIN_KEY`: Admin dashboard authentication key

### Security
- `ALLOW_INSECURE_DECRYPTION`: Enable server-side decryption fallback for HTTP/intranet deployments (default: `false`). When enabled, the key/password is sent to the server for decryption.

## Database Setup

Database migrations run automatically on server startup via `drizzle-orm/migrator`. To add schema changes:

1. Edit `src/db/schema.ts`
2. Run `bun run db:generate` to create a migration
3. Commit the `drizzle/` directory (includes `meta/_journal.json`)
4. Deploy — migrations execute on startup

Additional database commands:
- `bun run db:push` — push schema directly for fast local iteration (no migration files)
- `bun run db:migrate` — run migrations manually
- `bun run db:studio` — open Drizzle Studio for visual database browsing

The database uses SQLite with WAL mode enabled for better concurrent read performance.

## Deployment

### Docker

```bash
docker build -t claudereview .
docker run -p 3000:3000 -v ./data:/app/data claudereview
```

### Kubernetes

SQLite stores data in a local file, so for K8s deployment:
- Use a PersistentVolumeClaim to persist `/app/data`
- Run as single replica (SQLite doesn't support concurrent writes from multiple instances)
- Set `DATABASE_PATH=/app/data/claudereview.db`

### Railway

```bash
railway up
```

Required Railway services:
- Persistent volume for SQLite data

## License

MIT
