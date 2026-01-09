import type { ParsedSession, ParsedMessage, SessionMetadata } from './types.ts';

/**
 * Format a session as readable Markdown text for clipboard
 */
export function formatSessionAsMarkdown(session: ParsedSession): string {
  const lines: string[] = [];

  // Header
  lines.push(`# ${escapeMarkdown(session.title)}`);
  lines.push('');

  // Metadata section
  lines.push('## Session Info');
  lines.push('');
  lines.push(`- **Source**: ${session.source === 'codex' ? 'Codex CLI' : session.source === 'gemini' ? 'Gemini CLI' : 'Claude Code'}`);
  lines.push(`- **Messages**: ${session.metadata.messageCount}`);
  lines.push(`- **Duration**: ${formatDuration(session.metadata.durationSeconds)}`);
  lines.push(`- **Tools Used**: ${session.metadata.toolCount}`);

  // Token info
  if (session.metadata.actualInputTokens) {
    const total = session.metadata.actualInputTokens + (session.metadata.actualOutputTokens || 0);
    lines.push(`- **Tokens**: ${Math.round(total / 1000)}K (${session.metadata.actualInputTokens.toLocaleString()} in, ${(session.metadata.actualOutputTokens || 0).toLocaleString()} out)`);
  } else if (session.metadata.estimatedTokens) {
    lines.push(`- **Tokens**: ~${Math.round(session.metadata.estimatedTokens / 1000)}K (estimated)`);
  }

  // Model (Codex-specific)
  if (session.metadata.model) {
    lines.push(`- **Model**: ${session.metadata.model}`);
  }

  // Git context
  if (session.metadata.gitRepo || session.metadata.gitBranch) {
    lines.push('');
    lines.push('### Git Context');
    if (session.metadata.gitRepo) {
      lines.push(`- **Repo**: ${formatGitUrl(session.metadata.gitRepo)}`);
    }
    if (session.metadata.gitBranch) {
      lines.push(`- **Branch**: ${session.metadata.gitBranch}`);
    }
    if (session.metadata.gitCommit) {
      lines.push(`- **Commit**: \`${session.metadata.gitCommit.slice(0, 7)}\``);
    }
  }

  // Tool summary
  if (Object.keys(session.metadata.tools).length > 0) {
    lines.push('');
    lines.push('### Tools Summary');
    const sortedTools = Object.entries(session.metadata.tools)
      .sort((a, b) => b[1] - a[1]);
    for (const [tool, count] of sortedTools) {
      lines.push(`- ${tool}: ${count}x`);
    }
  }

  // Key moments
  const { filesCreated, filesModified, commandsRun } = session.metadata;
  const hasKeyMoments =
    (filesCreated?.length || 0) +
    (filesModified?.length || 0) +
    (commandsRun?.length || 0) > 0;

  if (hasKeyMoments) {
    lines.push('');
    lines.push('### Key Moments');

    if (filesCreated && filesCreated.length > 0) {
      lines.push('');
      lines.push('**Files Created:**');
      for (const file of filesCreated.slice(0, 10)) {
        lines.push(`- \`${basename(file)}\``);
      }
      if (filesCreated.length > 10) {
        lines.push(`- ...and ${filesCreated.length - 10} more`);
      }
    }

    if (filesModified && filesModified.length > 0) {
      lines.push('');
      lines.push('**Files Modified:**');
      for (const file of filesModified.slice(0, 10)) {
        lines.push(`- \`${basename(file)}\``);
      }
      if (filesModified.length > 10) {
        lines.push(`- ...and ${filesModified.length - 10} more`);
      }
    }

    if (commandsRun && commandsRun.length > 0) {
      lines.push('');
      lines.push('**Commands Run:**');
      for (const cmd of commandsRun.slice(0, 5)) {
        lines.push(`- \`${cmd}\``);
      }
      if (commandsRun.length > 5) {
        lines.push(`- ...and ${commandsRun.length - 5} more`);
      }
    }
  }

  // Conversation
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Conversation');
  lines.push('');

  for (const msg of session.messages) {
    const formatted = formatMessage(msg);
    if (formatted) {
      lines.push(formatted);
      lines.push('');
    }
  }

  // Footer
  lines.push('---');
  lines.push(`*Exported from [claudereview](https://claudereview.com) on ${new Date().toISOString().split('T')[0]}*`);

  return lines.join('\n');
}

/**
 * Format a single message
 */
function formatMessage(msg: ParsedMessage): string {
  switch (msg.type) {
    case 'human':
      return `### User\n\n${msg.content}`;

    case 'assistant':
      return `### Assistant\n\n${msg.content}`;

    case 'tool_call': {
      const toolHeader = `**Tool: ${msg.toolName}**`;
      const toolContent = msg.toolInput
        ? formatToolInput(msg.toolName!, msg.toolInput)
        : msg.content;
      return `${toolHeader}\n\n\`\`\`\n${toolContent}\n\`\`\``;
    }

    case 'tool_result': {
      const output = msg.toolOutput || msg.content;
      const truncatedOutput = output.length > 2000
        ? output.slice(0, 2000) + '\n... (truncated)'
        : output;
      const errorLabel = msg.isError ? ' (error)' : '';
      return `<details>\n<summary>Tool Output${errorLabel}</summary>\n\n\`\`\`\n${truncatedOutput}\n\`\`\`\n</details>`;
    }

    default:
      return '';
  }
}

/**
 * Format tool input for display
 */
function formatToolInput(toolName: string, input: Record<string, unknown>): string {
  if (toolName === 'Bash' && input.command) {
    return `$ ${input.command}`;
  }
  if (toolName === 'Read' && input.file_path) {
    return `read ${input.file_path}`;
  }
  if (toolName === 'Write' && input.file_path) {
    return `write ${input.file_path}`;
  }
  if (toolName === 'Edit' && input.file_path) {
    return `edit ${input.file_path}`;
  }
  if (toolName === 'Glob' && input.pattern) {
    return `glob ${input.pattern}`;
  }
  if (toolName === 'Grep' && input.pattern) {
    return `grep ${input.pattern}`;
  }
  return JSON.stringify(input, null, 2);
}

/**
 * Format duration in human readable format
 */
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

/**
 * Format git URL for display (extract repo name if SSH URL)
 */
function formatGitUrl(url: string): string {
  // Convert SSH URL to display format
  // git@github.com:user/repo.git -> github.com/user/repo
  const sshMatch = url.match(/git@([^:]+):(.+?)(?:\.git)?$/);
  if (sshMatch) {
    return `${sshMatch[1]}/${sshMatch[2]}`;
  }
  // HTTPS URL - just strip .git suffix
  return url.replace(/\.git$/, '');
}

/**
 * Extract basename from file path
 */
function basename(path: string): string {
  return path.split('/').pop() || path;
}

/**
 * Escape markdown special characters in text
 */
function escapeMarkdown(text: string): string {
  // Only escape in title context - don't break formatting
  return text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Format session as plain text (alternative to Markdown)
 */
export function formatSessionAsPlainText(session: ParsedSession): string {
  const lines: string[] = [];

  // Header
  lines.push(`SESSION: ${session.title}`);
  lines.push(`Source: ${session.source === 'codex' ? 'Codex CLI' : session.source === 'gemini' ? 'Gemini CLI' : 'Claude Code'}`);
  lines.push(`Messages: ${session.metadata.messageCount} | Tools: ${session.metadata.toolCount} | Duration: ${formatDuration(session.metadata.durationSeconds)}`);
  lines.push('');
  lines.push('='.repeat(80));
  lines.push('');

  // Conversation
  for (const msg of session.messages) {
    switch (msg.type) {
      case 'human':
        lines.push(`[USER]`);
        lines.push(msg.content);
        lines.push('');
        break;

      case 'assistant':
        lines.push(`[ASSISTANT]`);
        lines.push(msg.content);
        lines.push('');
        break;

      case 'tool_call':
        lines.push(`[TOOL: ${msg.toolName}]`);
        lines.push(msg.content);
        lines.push('');
        break;

      case 'tool_result':
        const output = msg.toolOutput || msg.content;
        const truncated = output.length > 1000 ? output.slice(0, 1000) + '\n...(truncated)' : output;
        lines.push(`[OUTPUT${msg.isError ? ' ERROR' : ''}]`);
        lines.push(truncated);
        lines.push('');
        break;
    }
  }

  lines.push('='.repeat(80));
  lines.push(`Exported from claudereview.com`);

  return lines.join('\n');
}
