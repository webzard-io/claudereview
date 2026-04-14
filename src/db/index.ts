import { drizzle } from 'drizzle-orm/bun-sqlite';
import { Database } from 'bun:sqlite';
import { dirname } from 'node:path';
import { mkdirSync, existsSync } from 'node:fs';
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';
import * as schema from './schema.ts';

// Get database path from environment, default to ./data/claudereview.db
const DATABASE_PATH = process.env.DATABASE_PATH || './data/claudereview.db';

// Ensure data directory exists
const dbDir = dirname(DATABASE_PATH);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

// Create SQLite connection using Bun's native SQLite
const sqlite = new Database(DATABASE_PATH);

// Enable WAL mode for better concurrent read performance
sqlite.exec('PRAGMA journal_mode = WAL;');

/**
 * Compatibility bridge for databases created before drizzle migrations.
 * The baseline migration only creates missing tables; it does not add
 * columns to existing tables that were created by older releases.
 */
const sessionsColumns = sqlite.query('PRAGMA table_info(sessions)').all() as Array<{ name: string }>;
if (sessionsColumns.length > 0) {
  const existingSessionsColumns = new Set(sessionsColumns.map((column) => column.name));

  const compatibilityMigrations = [
    { columnName: 'message_count', sql: 'ALTER TABLE sessions ADD COLUMN message_count INTEGER;' },
    { columnName: 'tool_count', sql: 'ALTER TABLE sessions ADD COLUMN tool_count INTEGER;' },
    { columnName: 'duration_seconds', sql: 'ALTER TABLE sessions ADD COLUMN duration_seconds INTEGER;' },
    { columnName: 'salt', sql: 'ALTER TABLE sessions ADD COLUMN salt TEXT;' },
    { columnName: 'owner_key', sql: 'ALTER TABLE sessions ADD COLUMN owner_key TEXT;' },
    { columnName: 'raw_json', sql: 'ALTER TABLE sessions ADD COLUMN raw_json TEXT;' },
    { columnName: 'view_count', sql: 'ALTER TABLE sessions ADD COLUMN view_count INTEGER DEFAULT 0 NOT NULL;' },
  ];

  for (const migration of compatibilityMigrations) {
    if (!existingSessionsColumns.has(migration.columnName)) {
      sqlite.exec(migration.sql);
    }
  }
}

// Create drizzle instance
export const db = drizzle(sqlite, { schema });

// Resolve migrations folder relative to this file, not process.cwd().
const migrationsFolder = decodeURIComponent(new URL('../../drizzle', import.meta.url).pathname);
migrate(db, { migrationsFolder });

// Schema assertion: fail fast if the compatibility bridge did not align the schema.
const cols = sqlite.query('PRAGMA table_info(sessions)').all() as Array<{ name: string }>;
const colNames = new Set(cols.map(c => c.name));
const required = ['message_count', 'tool_count', 'duration_seconds', 'salt', 'owner_key', 'raw_json', 'view_count'];
const missing = required.filter(c => !colNames.has(c));
if (missing.length > 0) {
  throw new Error(
    `Schema assertion failed: sessions table is missing columns: ${missing.join(', ')}. ` +
    'The compatibility bridge did not fully align this database.'
  );
}

// Re-export schema
export * from './schema.ts';
