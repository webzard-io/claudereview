CREATE TABLE IF NOT EXISTS `api_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`key_hash` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`last_used_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_api_keys_user_id` ON `api_keys` (`user_id`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_api_keys_key_hash` ON `api_keys` (`key_hash`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `session_views` (
	`id` text PRIMARY KEY NOT NULL,
	`session_id` text NOT NULL,
	`country` text,
	`city` text,
	`latitude` text,
	`longitude` text,
	`viewed_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`session_id`) REFERENCES `sessions`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_session_views_session_id` ON `session_views` (`session_id`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_session_views_viewed_at` ON `session_views` (`viewed_at`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text,
	`title` text,
	`message_count` integer,
	`tool_count` integer,
	`duration_seconds` integer,
	`visibility` text NOT NULL,
	`encrypted_blob` text NOT NULL,
	`iv` text NOT NULL,
	`salt` text,
	`owner_key` text,
	`raw_json` text,
	`view_count` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`expires_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_sessions_user_id` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_sessions_created_at` ON `sessions` (`created_at`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `users` (
	`id` text PRIMARY KEY NOT NULL,
	`github_id` text NOT NULL,
	`github_username` text NOT NULL,
	`github_avatar_url` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `users_github_id_unique` ON `users` (`github_id`);