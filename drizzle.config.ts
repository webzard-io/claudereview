import { defineConfig } from 'drizzle-kit';

const DATABASE_PATH = process.env.DATABASE_PATH || './data/claudereview.db';

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'sqlite',
  dbCredentials: {
    url: DATABASE_PATH,
  },
});
