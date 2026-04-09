# 设计：从手动 SQL 迁移到 Drizzle Migrate

**日期**: 2026-04-09
**状态**: Approved
**作者**: xingyu + Claude

## 问题

项目维护了两套需要手动同步的数据库定义：

1. `src/db/schema.ts` — Drizzle ORM schema（应用代码的唯一真实来源）
2. `src/db/index.ts` L27-L104 — 手写的 `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ADD COLUMN` SQL（运行时建表逻辑）

这已经导致了漂移：`sessions.raw_json` 在 `schema.ts:26` 中定义，但在 `index.ts` 的 `CREATE TABLE` 块和 `ALTER TABLE` 迁移逻辑中都缺失。

### 目标

1. 消除重复的 schema 定义
2. 服务启动时自动执行迁移
3. Docker 镜像包含已提交的 migration 文件
4. 为现有生产数据库提供安全的升级路径

### 非目标

- 多副本 / 分布式 SQLite 支持
- 自动降级 / 回滚（手动 SQL 回滚可接受）
- CI 流水线实现（记录为后续工作）

## 设计

### Phase 1：兼容修复 — 对齐现有数据库到 schema.ts

**目的**：确保所有生产数据库在切换到 Drizzle Migrate 之前与 `schema.ts` 一致。

**`src/db/index.ts` 变更**：

在 `ALTER TABLE` 迁移块中补上缺失的 `raw_json` 列：

```typescript
if (!existingSessionsColumns.has('raw_json')) {
  sqlite.exec('ALTER TABLE sessions ADD COLUMN raw_json TEXT;');
}
```

**部署**：发布此修复，部署到生产环境，确认所有数据库已对齐。

### Phase 2：生成 Baseline Migration

**步骤**：

1. 运行 `drizzle-kit generate` 在 `./drizzle/` 中生成初始 migration
2. 手动编辑生成的 SQL：将 `CREATE TABLE` 改为 `CREATE TABLE IF NOT EXISTS`，`CREATE INDEX` 改为 `CREATE INDEX IF NOT EXISTS` — 确保 baseline 对新库（无表）和已对齐的旧库都安全
3. 将**整个** `drizzle/` 目录提交到 git，包括：
   - `drizzle/XXXX_*.sql` — migration SQL 文件
   - `drizzle/meta/_journal.json` — 迁移日志（记录迁移顺序和校验和）
   - `drizzle/meta/XXXX_snapshot.json` — schema 快照

`meta/` 子目录至关重要：`migrate()` 通过读取 `_journal.json` 来判断哪些迁移已执行及执行顺序。缺少此文件将导致运行时错误。

**为什么只在 baseline 中使用 `IF NOT EXISTS`**：这是针对 baseline migration 的一次性让步。Phase 1 对齐现有数据库后，baseline 对旧库是空操作，对新库是完整初始化。后续所有 migration 将使用标准的 ALTER/CREATE，不再需要 `IF NOT EXISTS`。

### Phase 3：切换到 migrate()

**`src/db/index.ts` 变更**：

删除 L27-L104（所有手写的 `CREATE TABLE` + `ALTER TABLE` 逻辑），替换为：

```typescript
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';

// Run migrations on startup
migrate(db, { migrationsFolder: './drizzle' });
```

最终 `src/db/index.ts` 结构如下（省略了 mkdirSync 等辅助 import）：

```typescript
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { Database } from 'bun:sqlite';
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';
import * as schema from './schema.ts';

// Database path and directory setup (unchanged)
const DATABASE_PATH = process.env.DATABASE_PATH || './data/claudereview.db';
// ... mkdirSync logic ...

const sqlite = new Database(DATABASE_PATH);
sqlite.exec('PRAGMA journal_mode = WAL;');

// Create drizzle instance
export const db = drizzle(sqlite, { schema });

// Run all pending migrations on startup
migrate(db, { migrationsFolder: './drizzle' });

export * from './schema.ts';
```

**关于 import 副作用**：`migrate()` 在模块顶层执行，意味着任何 import `src/db/index.ts` 的文件都会触发迁移 — 包括 CLI 命令如 `bun run cli list`。这与当前行为一致（手写的 `CREATE TABLE IF NOT EXISTS` 也在 import 时执行），因此不是退步。但与 `CREATE TABLE IF NOT EXISTS` 的幂等静默不同，`migrate()` 在磁盘上找不到 migration 文件时会抛出异常。需确保 `drizzle/` 始终与应用一起部署。

**`Dockerfile` 变更**：

当前 Dockerfile 在 builder 阶段安装构建工具（python3, make, g++）和 better-sqlite3 用于 drizzle-kit 的原生依赖。使用 migrate() 后，运行时不再需要 drizzle-kit。

生产阶段变更：
- **新增**：`COPY --from=builder /app/drizzle ./drizzle`（migration 文件）
- **移除**：`COPY --from=builder /app/drizzle.config.ts ./`（运行时不再需要）

builder 阶段保持不变，因为开发时仍需要 drizzle-kit。

```dockerfile
# 在生产阶段，复制 migration 文件（包含 meta/ 子目录）
COPY --from=builder /app/drizzle ./drizzle
```

生产环境不需要 drizzle-kit — migration 文件已预生成并提交到 git。

**`package.json` 变更**：

drizzle-kit 保持 devDependency 不变。新增脚本：

```json
"db:migrate": "bun run src/db/migrate.ts"
```

用于手动测试迁移（一个简单的 import `db/index.ts` 的脚本）。

### Phase 4：文档和流程

**README.md L151-153**：从：

> The database schema is created on startup by `src/db/index.ts`.

更新为：

> Database migrations run automatically on server startup. To add schema changes:
> 1. Edit `src/db/schema.ts`
> 2. Run `bun run db:generate` to create a migration
> 3. Commit the `drizzle/` directory
> 4. Deploy — migrations execute on startup

**CLAUDE.md Commands 节**：补充 `db:generate` 和 `db:migrate` 说明。

**后续 CI 检查**（不在本 spec 范围，记录为后续工作）：
- 如果 `src/db/schema.ts` 有变更但 `drizzle/` 目录没有对应变更则 CI 失败。

## 开发工作流

```
日常开发  →  bun run db:push    （快速迭代，不生成 migration 文件）
Schema 稳定  →  bun run db:generate （生成 migration SQL）
提交  →  git add drizzle/ && git commit
部署  →  服务启动 → migrate() 执行待运行的 migration
```

## 现有部署的升级路径

```
v0.0.5（当前）  →  Phase 1 发布（修复漂移）  →  Phase 3 发布（migrate()）
                    部署，确认数据库已对齐         部署，启动时自动迁移
```

对于运行现有实例的运维人员：
1. 先升级到 Phase 1 版本 — 补齐所有缺失的列
2. 再升级到 Phase 3 版本 — migrate() 接管，baseline 因表已存在（`IF NOT EXISTS`）而为空操作

## 变更文件

```plaintext
+------------------------------+-----------------------------------------------------+
|  文件                         |  变更说明                                            |
+------------------------------+-----------------------------------------------------+
|  src/db/index.ts             |  Phase 1: 补 raw_json 迁移; Phase 3: 替换为 migrate() |
|  Dockerfile                  |  新增 COPY drizzle/, 移除 COPY drizzle.config.ts      |
|  package.json                |  新增 db:migrate 脚本                                 |
|  README.md                   |  更新数据库设置章节                                    |
|  CLAUDE.md                   |  补充 db:generate / db:migrate 命令说明               |
+------------------------------+-----------------------------------------------------+
|  drizzle/ (新增)              |  Migration 文件目录（生成后提交到 git）                 |
|                              |  包含：SQL 文件, meta/_journal.json, meta/*_snapshot   |
+------------------------------+-----------------------------------------------------+
```

## 风险和缓解措施

```plaintext
+-------------------------------------------+---------------------------------------------------+
|  风险                                      |  缓解措施                                          |
+-------------------------------------------+---------------------------------------------------+
|  Baseline migration 在现有库上失败          |  Phase 1 先对齐；baseline 使用 IF NOT EXISTS        |
|  开发者忘记运行 db:generate                 |  后续 CI 检查；在 README 和 CLAUDE.md 中文档化       |
|  drizzle-kit generate 生成意外 SQL          |  提交前人工 review；baseline 手动验证                |
|  SQLite ALTER TABLE 限制（不支持 DROP COLUMN）|  项目规模可接受；破坏性变更很少                      |
|  migrate() 因缺少 drizzle/ 文件而失败       |  Dockerfile 显式 COPY drizzle/；CI 可验证目录存在    |
|  数据库中出现 __drizzle_migrations 表       |  预期行为：migrate() 自动创建此表追踪已执行的迁移，    |
|                                           |  运维人员不应将其视为 schema 漂移                    |
+-------------------------------------------+---------------------------------------------------+
```
