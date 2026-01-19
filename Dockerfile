ARG BUN_IMAGE=oven/bun:1
FROM ${BUN_IMAGE} AS builder

WORKDIR /app

# Copy package files
COPY package.json bun.lock* ./

# Install dependencies
RUN bun install

# Copy source code
COPY . .

# Production image
FROM ${BUN_IMAGE} AS production

WORKDIR /app

# Copy from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/src ./src
COPY --from=builder /app/package.json ./
COPY --from=builder /app/drizzle.config.ts ./

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
