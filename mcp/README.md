# claudereview MCP Server

Share Claude Code sessions directly from Claude using the Model Context Protocol.

## Installation

Add to your Claude settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "claudereview": {
      "command": "bun",
      "args": ["run", "/path/to/claudereview/mcp/server.ts"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "claudereview": {
      "command": "claudereview-mcp"
    }
  }
}
```

## Tools

### `list_sessions`

List available Claude Code sessions.

```
list_sessions(limit?: number)
```

### `share_session`

Share a session and get an encrypted URL.

```
share_session(session_id: string, title?: string)
```

Use `session_id: "last"` to share the most recent session.

## Usage

Once configured, just ask Claude:

- "Share this session"
- "List my recent sessions"
- "Share session abc123 with title 'Bug fix review'"
