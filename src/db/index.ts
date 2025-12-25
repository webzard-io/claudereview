import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.ts';

// Get database URL from environment
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn('DATABASE_URL not set - database features will not work');
}

// Create postgres connection
const client = DATABASE_URL
  ? postgres(DATABASE_URL, { prepare: false })
  : null;

// Create drizzle instance
export const db = client ? drizzle(client, { schema }) : null;

// Re-export schema
export * from './schema.ts';
