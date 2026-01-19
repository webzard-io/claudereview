import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

// Users table (from GitHub OAuth)
export const users = sqliteTable('users', {
  id: text('id').primaryKey(), // nanoid
  githubId: text('github_id').unique().notNull(),
  githubUsername: text('github_username').notNull(),
  githubAvatarUrl: text('github_avatar_url'),
  createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`).notNull(),
});

// Sessions table (stores encrypted session data)
export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(), // short nanoid for URLs
  userId: text('user_id').references(() => users.id), // nullable for anonymous uploads
  title: text('title'), // nullable for private sessions (no metadata stored)
  messageCount: integer('message_count'), // nullable for private sessions
  toolCount: integer('tool_count'), // nullable for private sessions
  durationSeconds: integer('duration_seconds'), // nullable for private sessions
  visibility: text('visibility', { enum: ['public', 'private'] }).notNull(),
  encryptedBlob: text('encrypted_blob').notNull(), // base64 encoded
  iv: text('iv').notNull(), // initialization vector
  salt: text('salt'), // for private sessions (password key derivation)
  ownerKey: text('owner_key'), // encryption key for owner viewing (only stored for authenticated uploads)
  viewCount: integer('view_count').default(0).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`).notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }), // optional expiration
}, (table) => ({
  sessionsUserIdIndex: index('idx_sessions_user_id').on(table.userId),
  sessionsCreatedAtIndex: index('idx_sessions_created_at').on(table.createdAt),
}));

// API Keys for CLI authentication
export const apiKeys = sqliteTable('api_keys', {
  id: text('id').primaryKey(), // nanoid
  userId: text('user_id').references(() => users.id).notNull(),
  keyHash: text('key_hash').notNull(), // hashed API key
  name: text('name').notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`).notNull(),
  lastUsedAt: integer('last_used_at', { mode: 'timestamp' }),
}, (table) => ({
  apiKeysUserIdIndex: index('idx_api_keys_user_id').on(table.userId),
  apiKeysKeyHashIndex: index('idx_api_keys_key_hash').on(table.keyHash),
}));

// Session views for analytics (with location)
export const sessionViews = sqliteTable('session_views', {
  id: text('id').primaryKey(), // nanoid
  sessionId: text('session_id').references(() => sessions.id).notNull(),
  country: text('country'), // ISO country code
  city: text('city'),
  latitude: text('latitude'),
  longitude: text('longitude'),
  viewedAt: integer('viewed_at', { mode: 'timestamp' }).default(sql`(unixepoch())`).notNull(),
}, (table) => ({
  sessionViewsSessionIdIndex: index('idx_session_views_session_id').on(table.sessionId),
  sessionViewsViewedAtIndex: index('idx_session_views_viewed_at').on(table.viewedAt),
}));

// Type exports
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type ApiKey = typeof apiKeys.$inferSelect;
export type NewApiKey = typeof apiKeys.$inferInsert;
