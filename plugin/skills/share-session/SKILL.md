---
name: share-session
description: Share the current Claude Code session to claudereview.com for code review. Use this when the user wants to share their session, get a link to the conversation, or create a shareable review of the work done.
allowed-tools: Read, Bash, Glob
---

# Share Session Skill

This skill uploads the current Claude Code session to claudereview.com and returns an encrypted shareable link.

## When to Use

- User says "share this session", "get a shareable link", "share for code review"
- User wants to share their work with teammates
- User wants to create a record of the conversation

## How to Share

### Step 1: Find the Current Session

The current session is stored in `~/.claude/projects/`. Find the most recent `.jsonl` file:

```bash
ls -t ~/.claude/projects/*/*.jsonl | head -1
```

### Step 2: Read and Parse the Session

Read the session file content. It's in JSONL format with messages.

### Step 3: Upload to claudereview.com

Make a POST request to upload the session:

```bash
# Generate encryption key and encrypt session
SESSION_CONTENT=$(cat <session_file>)

# Upload (the session should be encrypted client-side, but for simplicity we'll use the API)
curl -X POST https://claudereview.com/api/upload \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedBlob": "<base64_encrypted_content>",
    "iv": "<base64_iv>",
    "visibility": "public",
    "metadata": {
      "title": "<session_title>",
      "messageCount": <count>,
      "toolCount": <count>,
      "durationSeconds": <duration>
    }
  }'
```

### Step 4: Return the Link

The API returns:
```json
{
  "id": "abc123",
  "url": "https://claudereview.com/s/abc123"
}
```

For public sessions, append the encryption key to the URL fragment:
```
https://claudereview.com/s/abc123#key=<base64_key>
```

## Privacy Note

- Sessions are encrypted before upload
- For public links: encryption key is in the URL fragment (never sent to server)
- For password-protected links: key is derived from password client-side
- Only people with the full link (or password) can view the session

## Alternative: Use the CLI

If the user has `ccshare` installed:
```bash
ccshare share --last
```
