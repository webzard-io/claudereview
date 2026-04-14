ARG BUN_IMAGE=oven/bun:1
FROM ${BUN_IMAGE} AS builder

WORKDIR /app

# Install build tools and Node.js for native addon compilation
RUN apt-get update && apt-get install -y python3 make g++ nodejs npm --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package.json bun.lock* ./

# Install dependencies with bun
RUN bun install

# Copy source code
COPY . .

# Production image
FROM ${BUN_IMAGE} AS production

WORKDIR /app

# Copy from builder (no Node.js or drizzle-kit needed at runtime)
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/src ./src
COPY --from=builder /app/package.json ./
COPY --from=builder /app/drizzle ./drizzle

# Create data directory for SQLite
RUN mkdir -p /app/data

# Set environment
ENV NODE_ENV=production
ENV PORT=3000
ENV DATABASE_PATH=/app/data/claudereview.db

# Expose port and data volume
EXPOSE 3000
VOLUME ["/app/data"]

# Run the server
CMD ["bun", "run", "start"]
