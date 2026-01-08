import { readdir, stat, readFile } from 'fs/promises';
import { join, basename } from 'path';
import { homedir } from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import type { LocalSession, ParsedSession } from './types.ts';
import { parseSessionFile, parseSessionContent } from './parser.ts';
import { parseCodexSessionFile } from './codex-parser.ts';

const execAsync = promisify(exec);

const CLAUDE_PROJECTS_DIR = join(homedir(), '.claude', 'projects');
const CODEX_SESSIONS_DIR = join(homedir(), '.codex', 'sessions');

/**
 * List all available sessions across all projects (Claude Code and Codex)
 */
export async function listSessions(): Promise<LocalSession[]> {
  const claudeSessions = await listClaudeSessions();
  const codexSessions = await listCodexSessions();

  // Merge and sort by modification time
  const allSessions = [...claudeSessions, ...codexSessions];
  allSessions.sort((a, b) => b.modifiedAt.getTime() - a.modifiedAt.getTime());

  return allSessions;
}

/**
 * List Claude Code sessions from ~/.claude/projects/
 */
async function listClaudeSessions(): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    const projectDirs = await readdir(CLAUDE_PROJECTS_DIR);

    for (const projectDir of projectDirs) {
      const projectPath = join(CLAUDE_PROJECTS_DIR, projectDir);
      const projectStat = await stat(projectPath);

      if (!projectStat.isDirectory()) continue;

      const files = await readdir(projectPath);
      const sessionFiles = files.filter(f => f.endsWith('.jsonl'));

      for (const file of sessionFiles) {
        const filePath = join(projectPath, file);
        const fileStat = await stat(filePath);

        // Extract session ID from filename
        const id = file.replace('.jsonl', '');

        // Try to get title from first line (summary)
        let title: string | undefined;
        try {
          const content = await readFile(filePath, 'utf-8');
          const firstLine = content.split('\n')[0];
          if (firstLine) {
            const parsed = JSON.parse(firstLine);
            if (parsed.type === 'summary' && parsed.summary) {
              title = parsed.summary;
            }
          }
        } catch {
          // Ignore errors reading title
        }

        sessions.push({
          id,
          path: filePath,
          projectPath: await decodeProjectPath(projectDir),
          modifiedAt: fileStat.mtime,
          title,
          source: 'claude',
        });
      }
    }

    return sessions;
  } catch (error) {
    console.error('Error listing Claude sessions:', error);
    return [];
  }
}

/**
 * List Codex sessions from ~/.codex/sessions/YYYY/MM/DD/
 */
async function listCodexSessions(): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    // Walk year directories
    const years = await readdir(CODEX_SESSIONS_DIR);

    for (const year of years) {
      const yearPath = join(CODEX_SESSIONS_DIR, year);
      let yearStat;
      try {
        yearStat = await stat(yearPath);
      } catch {
        continue;
      }
      if (!yearStat.isDirectory()) continue;

      // Walk month directories
      const months = await readdir(yearPath);
      for (const month of months) {
        const monthPath = join(yearPath, month);
        let monthStat;
        try {
          monthStat = await stat(monthPath);
        } catch {
          continue;
        }
        if (!monthStat.isDirectory()) continue;

        // Walk day directories
        const days = await readdir(monthPath);
        for (const day of days) {
          const dayPath = join(monthPath, day);
          let dayStat;
          try {
            dayStat = await stat(dayPath);
          } catch {
            continue;
          }
          if (!dayStat.isDirectory()) continue;

          // Find session files
          const files = await readdir(dayPath);
          for (const file of files.filter(f => f.endsWith('.jsonl'))) {
            const filePath = join(dayPath, file);
            const fileStat = await stat(filePath);

            // Extract session ID (UUID) from filename like rollout-YYYY-MM-DDTHH-MM-SS-{uuid}.jsonl
            const idMatch = file.match(/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.jsonl$/i);
            const id = idMatch?.[1] ?? file.replace('.jsonl', '');

            // Try to get project path (cwd) from session_meta
            let projectPath = '';
            let title: string | undefined;
            try {
              const content = await readFile(filePath, 'utf-8');
              const firstLine = content.split('\n')[0];
              if (firstLine) {
                const parsed = JSON.parse(firstLine);
                if (parsed.type === 'session_meta' && parsed.payload?.cwd) {
                  projectPath = parsed.payload.cwd;
                }
              }
            } catch {
              // Ignore errors reading metadata
            }

            sessions.push({
              id,
              path: filePath,
              projectPath,
              modifiedAt: fileStat.mtime,
              title,
              source: 'codex',
            });
          }
        }
      }
    }

    return sessions;
  } catch (error) {
    // Codex directory may not exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error('Error listing Codex sessions:', error);
    }
    return [];
  }
}

/**
 * Find sessions for a specific project directory
 */
export async function listSessionsForProject(projectDir: string): Promise<LocalSession[]> {
  const allSessions = await listSessions();
  const normalizedProject = normalizeProjectPath(projectDir);

  return allSessions.filter(session => {
    const normalizedSession = normalizeProjectPath(session.projectPath);
    return normalizedSession === normalizedProject;
  });
}

/**
 * Get a session by ID (searches all projects)
 */
export async function getSession(sessionId: string): Promise<LocalSession | null> {
  const sessions = await listSessions();

  // Try exact match first
  let session = sessions.find(s => s.id === sessionId);
  if (session) return session;

  // Try partial match (prefix)
  const matches = sessions.filter(s => s.id.startsWith(sessionId));
  if (matches.length === 1) return matches[0] ?? null;
  if (matches.length > 1) {
    throw new Error(`Ambiguous session ID "${sessionId}" matches ${matches.length} sessions`);
  }

  // Try index (1-based)
  const index = parseInt(sessionId, 10);
  if (!isNaN(index) && index >= 1 && index <= sessions.length) {
    return sessions[index - 1] ?? null;
  }

  return null;
}

/**
 * Get the most recent session
 */
export async function getLastSession(): Promise<LocalSession | null> {
  const sessions = await listSessions();
  return sessions[0] || null;
}

/**
 * Parse a session by ID (auto-detects Claude vs Codex)
 */
export async function parseSession(sessionId: string): Promise<ParsedSession> {
  const session = await getSession(sessionId);
  if (!session) {
    throw new Error(`Session not found: ${sessionId}`);
  }

  if (session.source === 'codex') {
    return parseCodexSessionFile(session.path);
  }
  return parseSessionFile(session.path);
}

/**
 * Parse the most recent session
 */
export async function parseLastSession(): Promise<ParsedSession> {
  const session = await getLastSession();
  if (!session) {
    throw new Error('No sessions found');
  }

  if (session.source === 'codex') {
    return parseCodexSessionFile(session.path);
  }
  return parseSessionFile(session.path);
}

/**
 * Decode the project directory name to actual path
 * e.g., "-Users-vignesh-myproject" -> "/Users/vignesh/myproject"
 *
 * Note: This encoding is lossy - a hyphen in a directory name (e.g., "my-app")
 * becomes indistinguishable from a path separator. We try to find the actual
 * path by walking up from the most specific interpretation.
 */
async function decodeProjectPath(encodedPath: string): Promise<string> {
  // Simple decode: replace leading dash and subsequent dashes with path separators
  const simpleDecoded = '/' + encodedPath.replace(/^-/, '').replace(/-/g, '/');

  // Try to validate the path exists
  try {
    await stat(simpleDecoded);
    return simpleDecoded;
  } catch {
    // Path doesn't exist, try to find a valid parent path
    // by progressively joining segments
  }

  // Try building path by checking each level
  const segments = encodedPath.replace(/^-/, '').split('-');
  let currentPath = '';

  for (let i = 0; i < segments.length; i++) {
    const testPath = currentPath + '/' + segments[i];
    try {
      await stat(testPath);
      currentPath = testPath;
    } catch {
      // This segment might need to be joined with the next
      // Try joining remaining segments with hyphens progressively
      let remaining = segments.slice(i).join('-');
      const testFullPath = currentPath + '/' + remaining;
      try {
        await stat(testFullPath);
        return testFullPath;
      } catch {
        // Keep trying with fewer hyphens converted to path separators
        currentPath = testPath;
      }
    }
  }

  // If we can't validate, return the simple decoded version
  // (it's only used for display/filtering anyway)
  return simpleDecoded;
}

/**
 * Normalize a project path for comparison
 */
function normalizeProjectPath(path: string): string {
  return path.replace(/\/$/, '').toLowerCase();
}

/**
 * Format duration in human readable format
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.round((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

/**
 * Format relative time
 */
export function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}

/**
 * Git context information
 */
export interface GitContext {
  gitRepo?: string;
  gitBranch?: string;
  gitCommit?: string;
}

/**
 * Detect git context from a project directory
 */
export async function detectGitContext(projectPath: string): Promise<GitContext> {
  const context: GitContext = {};

  try {
    // Get remote origin URL
    const { stdout: remoteUrl } = await execAsync('git remote get-url origin', { cwd: projectPath });
    context.gitRepo = remoteUrl.trim();
  } catch {
    // Not a git repo or no remote
  }

  try {
    // Get current branch
    const { stdout: branch } = await execAsync('git branch --show-current', { cwd: projectPath });
    context.gitBranch = branch.trim() || undefined;
  } catch {
    // No branch info
  }

  try {
    // Get current commit hash
    const { stdout: commit } = await execAsync('git rev-parse HEAD', { cwd: projectPath });
    context.gitCommit = commit.trim();
  } catch {
    // No commit info
  }

  return context;
}

/**
 * Parse a session with git context
 */
export async function parseSessionWithGit(sessionId: string): Promise<ParsedSession> {
  const session = await getSession(sessionId);
  if (!session) {
    throw new Error(`Session not found: ${sessionId}`);
  }

  const parsed = session.source === 'codex'
    ? await parseCodexSessionFile(session.path)
    : await parseSessionFile(session.path);

  // Try to detect git context from the project directory
  // (Codex may already have git context from session_meta, but we'll override with fresh data)
  if (session.projectPath) {
    const gitContext = await detectGitContext(session.projectPath);

    // Merge git context into metadata
    parsed.metadata = {
      ...parsed.metadata,
      ...gitContext,
    };
  }

  return parsed;
}
