import pg from "pg";
import { performance } from "node:perf_hooks";
import crypto from "node:crypto";
import { trace, SpanStatusCode, context } from "@opentelemetry/api";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { getCurrentRoute } from "../api/middleware/requestContext.js";
import { AppError, ErrorCode } from "../api/middleware/errors.js";

const tracer = trace.getTracer("stellaryield-db");

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.db.url,
  min: config.db.poolMin,
  max: config.db.poolMax,
  idleTimeoutMillis: config.db.idleTimeoutMs,
  query_timeout: config.db.queryTimeoutMs,
});

export function redactQueryParameters(sql: string): string {
  return sql
    .replace(/'[^']*'/g, "'[REDACTED]'")
    .replace(/"[^"]*"/g, '"[REDACTED]"')
    .trim();
}

async function logSlowQuery(sql: string, durationMs: number): Promise<void> {
  try {
    const queryHash = crypto.createHash("sha256").update(sql).digest("hex");
    const queryPreview = redactQueryParameters(sql).slice(0, 200);
    const route = getCurrentRoute();
    await pool.query(
      `INSERT INTO slow_query_log (query_hash, query_preview, duration_ms, route)
       VALUES ($1, $2, $3, $4)`,
      [queryHash, queryPreview, durationMs, route],
    );
  } catch (err) {
    logger.error({ err }, "Failed to log slow query");
  }
}

// Prepared statement registry for hot queries
const preparedStatements = new Map<string, { name: string; text: string }>();

export function registerPreparedStatement(name: string, text: string): void {
  preparedStatements.set(name, { name, text });
  logger.debug({ name }, "Registered prepared statement");
}

export async function query<T = Record<string, unknown>>(
  sql: string,
  params?: unknown[],
  options?: { timeoutMs?: number },
): Promise<T[]> {
  const span = tracer.startSpan("db.query", {}, context.active());
  span.setAttribute("db.statement", sql.slice(0, 80));

  const start = performance.now();
  try {
    let result: pg.QueryResult;
    const timeoutMs = options?.timeoutMs;
    if (timeoutMs) {
      const client = await pool.connect();
      try {
        await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
        result = await client.query(sql, params);
      } catch (err: any) {
        if (err?.code === "57014") {
          throw new AppError(ErrorCode.QUERY_TIMEOUT, "Query timed out", 504);
        }
        throw err;
      } finally {
        client.release();
      }
    } else {
      result = await pool.query(sql, params);
    }

    const durationMs = performance.now() - start;
    const roundedMs = Math.round(durationMs * 100) / 100;

    span.setAttribute("db.response.rows", result.rowCount ?? 0);

    if (durationMs > config.db.slowQueryMs) {
      logger.warn(
        { sql, paramsCount: params?.length ?? 0, durationMs: roundedMs, rowCount: result.rowCount },
        "slow query",
      );
      if (!sql.includes("slow_query_log")) {
        logSlowQuery(sql, roundedMs).catch(() => {});
      }
    } else if (logger.level === "debug" || logger.level === "trace") {
      const firstLine = config.nodeEnv === "production" ? sql.slice(0, 80) : sql;
      logger.debug({ sql: firstLine, durationMs: roundedMs, rowCount: result.rowCount }, "query");
    }

    return result.rows as T[];
  } catch (err) {
    if (err instanceof AppError) throw err;
    span.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
    throw err;
  } finally {
    span.end();
  }
}

export async function queryPrepared<T = Record<string, unknown>>(
  name: string,
  params?: unknown[],
  options?: { timeoutMs?: number },
): Promise<T[]> {
  const stmt = preparedStatements.get(name);
  if (!stmt) {
    throw new Error(`Prepared statement "${name}" not registered`);
  }
  const timeoutMs = options?.timeoutMs;
  if (timeoutMs) {
    const client = await pool.connect();
    try {
      await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
      const result = await client.query({ name: stmt.name, text: stmt.text, values: params });
      return result.rows;
    } catch (err: any) {
      if (err?.code === "57014") {
        throw new AppError(ErrorCode.QUERY_TIMEOUT, "Query timed out", 504);
      }
      throw err;
    } finally {
      client.release();
    }
  }
  const result = await pool.query({ name: stmt.name, text: stmt.text, values: params });
  return result.rows;
}

async function prepareStatements(): Promise<void> {
  for (const [key, stmt] of preparedStatements) {
    try {
      await pool.query(`PREPARE ${stmt.name} AS ${stmt.text}`);
      logger.debug({ name: key }, "Prepared statement cached");
    } catch {
      // Statement may already be prepared — ignore
    }
  }
  logger.info({ count: preparedStatements.size }, "Prepared statements initialized");
}

async function validateConnection(): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("SELECT 1");
    logger.info("Database connection established");
  } finally {
    client.release();
  }
}

process.on("SIGTERM", async () => {
  logger.info("Shutting down database pool");
  await pool.end();
});

// ── Pool exhaustion alerting (#828) ───────────────────────────────────────────
// Every 10 s, log at error level if the number of queued connection requests
// exceeds DB_POOL_ALERT_WAITING (default 5). Healthy operation never logs here.
if (process.env["NODE_ENV"] !== "test") {
  setInterval(() => {
    const waiting = pool.waitingCount;
    if (waiting > config.dbPoolAlertWaiting) {
      logger.error(`DB pool exhaustion: ${waiting} connections waiting`);
    }
  }, 10_000).unref();
}

// Validate on startup — exit immediately if DATABASE_URL is unreachable
if (process.env["NODE_ENV"] !== "test") {
  validateConnection()
    .then(() => prepareStatements())
    .catch((err) => {
      logger.error(err, "Failed to connect to database");
      process.exit(1);
    });
}
