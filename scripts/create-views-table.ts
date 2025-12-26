import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

const sql = postgres(DATABASE_URL, { prepare: false });

async function run() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS session_views (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(id),
        country TEXT,
        city TEXT,
        latitude TEXT,
        longitude TEXT,
        viewed_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `;
    console.log('session_views table created successfully');

    // Create index for faster queries
    await sql`
      CREATE INDEX IF NOT EXISTS idx_session_views_viewed_at ON session_views(viewed_at)
    `;
    console.log('Index created successfully');

    await sql.end();
  } catch (e) {
    console.error('Error:', e);
    process.exit(1);
  }
}

run();
