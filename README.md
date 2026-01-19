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

# Preview the most recent session in browser
ccshare preview --last

# Export to HTML file
ccshare export --last -o session.html
```

## Features

### Security
- **E2E Encrypted**: Sessions encrypted before upload with AES-256-GCM
- **Key in URL Fragment**: Encryption key never sent to server (`#key=xxx`)
- **Password Protection**: Optional PBKDF2-derived keys for private shares

### Viewer
- **TUI Aesthetic**: Beautiful terminal-style dark/light theme
- **Search**: Full-text search with ⌘F
- **Collapsible Outputs**: Expand/collapse tool results
- **Syntax Highlighting**: Code blocks with language detection
- **Diff View**: Visual diffs for file edits
- **Key Moments**: Summary of files created/modified, commands run
- **Git Context**: Links to repo, branch, and commit
- **Deep Linking**: Link directly to specific messages
- **Token Estimates**: Rough usage statistics

### Export
- **Self-Contained HTML**: Exported files work offline
- **OG Meta Tags**: Rich previews when sharing links
- **Clipboard Copy**: Copy as formatted Markdown for pasting anywhere

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
1. CLI encrypts session with a random key
2. Uploads encrypted blob to claudereview.com
3. Returns URL with key in fragment: `claudereview.com/s/abc123#key=xxx`
4. The `#key=xxx` fragment is never sent to the server
5. Browser decrypts client-side

### Private Shares
1. CLI encrypts session with password-derived key (PBKDF2)
2. Uploads encrypted blob + salt
3. Returns URL without key: `claudereview.com/s/abc123`
4. Viewer prompts for password, derives key, decrypts

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

- `DATABASE_PATH`: SQLite database path (default: ./data/claudereview.db)
- `BASE_URL`: Public URL (default: https://claudereview.com)
- `SITE_NAME`: Site name for branding (default: claudereview)
- `PORT`: Server port (default: 3000)
- `CCSHARE_API_URL`: API URL for CLI (default: http://192.168.17.244:31935)
- `CCSHARE_API_KEY`: API key for authenticated uploads
- `ALLOW_INSECURE_DECRYPTION`: Enable server-side decryption fallback for HTTP/intranet (default: false, sends key/password to server)

## Database Setup

The database schema is created on startup by `src/db/index.ts`.

## Deployment

Deploy to Railway:

```bash
railway up
```

Required Railway services:
- Persistent volume for SQLite data

## License

MIT
