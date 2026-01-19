# claudereview-mcp

MCP server for sharing Claude Code, Codex CLI, and Gemini CLI sessions via [claudereview.com](https://claudereview.com).

## Installation

```bash
npm install -g smartx-claudereview-mcp
# or
bun add -g smartx-claudereview-mcp
```

Then add to `~/.mcp.json`:

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

## Authentication

To link shared sessions to your account:

1. Log in at [claudereview.com](https://claudereview.com) with GitHub
2. Go to Dashboard → Settings → API Keys
3. Create a new API key
4. Add it to your MCP config as shown above

Without an API key, sessions are shared anonymously and won't appear in your dashboard.

## Tools

### `list_sessions`

List available Claude Code, Codex CLI, and Gemini CLI sessions.

```
list_sessions(limit?: number)
```

Returns sessions with source indicator (`[Claude]`, `[Codex]`, or `[Gemini]`).

### `share_session`

Share a session and get an encrypted URL.

```
share_session(session_id: string, title?: string)
```

Use `session_id: "last"` to share the most recent session.

### `copy_session`

Copy a session as formatted Markdown text.

```
copy_session(session_id: string)
```

Returns the session content as Markdown with stats, git context, tools summary, and full conversation. Use this when you want to paste session content somewhere rather than sharing a URL.

## Usage

Once configured, just ask Claude:

- "Share this session"
- "List my recent sessions"
- "Share session abc123 with title 'Bug fix review'"
- "Copy the last session as text"
- "Give me the markdown for this session"

## Viewer Features

Shared sessions include a full-featured viewer:

- **Dark/Light Theme**: Toggle with button or system preference
- **Search**: Full-text search with ⌘F
- **Collapsible Outputs**: Expand/collapse tool results
- **Syntax Highlighting**: Code blocks with language detection
- **Diff View**: Visual diffs for Edit tool changes
- **Key Moments**: Summary of files created/modified, commands run
- **Git Context**: Links to repo, branch, and commit
- **Clickable Tool Badges**: Jump to tool usage instances
- **Token Estimates**: Rough usage statistics
- **Deep Linking**: Link to specific messages with #msg-N
- **OG Meta Tags**: Rich previews when sharing links
