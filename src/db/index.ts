import { drizzle } from 'drizzle-orm/bun-sqlite';
import { Database } from 'bun:sqlite';
import * as schema from './schema.ts';

// Get database path from environment, default to ./data/claudereview.db
const DATABASE_PATH = process.env.DATABASE_PATH || './data/claudereview.db';

// Ensure data directory exists
import { mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';

const dbDir = dirname(DATABASE_PATH);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

// Create SQLite connection using Bun's native SQLite
const sqlite = new Database(DATABASE_PATH);

// Enable WAL mode for better concurrent read performance
sqlite.exec('PRAGMA journal_mode = WAL;');

/**
 * Runtime schema bootstrap to avoid drizzle-kit in production.
 * Keep this SQL in sync with src/db/schema.ts.
 */
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    github_id TEXT UNIQUE NOT NULL,
    github_username TEXT NOT NULL,
    github_avatar_url TEXT,
    created_at INTEGER DEFAULT (unixepoch()) NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT REFERENCES users(id),
    title TEXT,
    message_count INTEGER,
    tool_count INTEGER,
    duration_seconds INTEGER,
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    encrypted_blob TEXT NOT NULL,
    iv TEXT NOT NULL,
    salt TEXT,
    owner_key TEXT,
    view_count INTEGER DEFAULT 0 NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()) NOT NULL,
    expires_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()) NOT NULL,
    last_used_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS session_views (
    id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    country TEXT,
    city TEXT,
    latitude TEXT,
    longitude TEXT,
    viewed_at INTEGER DEFAULT (unixepoch()) NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
  CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_session_views_session_id ON session_views(session_id);
  CREATE INDEX IF NOT EXISTS idx_session_views_viewed_at ON session_views(viewed_at);
`);

/**
 * Lightweight migration for existing databases.
 * Ensures older schemas get new columns without a formal migration system.
 */
const sessionsColumns = sqlite.query('PRAGMA table_info(sessions);').all() as Array<{ name: string }>;
const existingSessionsColumns = new Set(sessionsColumns.map((column) => column.name));

if (!existingSessionsColumns.has('message_count')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN message_count INTEGER;');
}
if (!existingSessionsColumns.has('tool_count')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN tool_count INTEGER;');
}
if (!existingSessionsColumns.has('duration_seconds')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN duration_seconds INTEGER;');
}
if (!existingSessionsColumns.has('salt')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN salt TEXT;');
}
if (!existingSessionsColumns.has('owner_key')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN owner_key TEXT;');
}
if (!existingSessionsColumns.has('view_count')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN view_count INTEGER DEFAULT 0 NOT NULL;');
}

// Create drizzle instance
export const db = drizzle(sqlite, { schema });

// Re-export schema
export * from './schema.ts';
