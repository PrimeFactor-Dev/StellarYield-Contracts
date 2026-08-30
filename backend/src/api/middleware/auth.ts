import { createHash } from "crypto";
import type { Request, Response, NextFunction } from "express";
import { query } from "../../db/index.js";
import { logger } from "../../logger.js";

interface ApiKey {
  id: number;
  role: string;
  label: string | null;
  expiresAt: Date | null;
}

declare module "express-serve-static-core" {
  interface Request {
    apiKey?: ApiKey;
  }
}

const READ_ONLY_METHODS = new Set(["GET", "HEAD"]);

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded.length > 0) {
    return forwarded[0].trim();
  }
  return req.socket?.remoteAddress ?? "unknown";
}

export function requireApiKey(options?: { role?: string; minRole?: "readonly" | "admin" }) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ip = getClientIp(req);
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Unauthorized", message: "Missing API key" });
      return;
    }

    const plaintext = authHeader.slice(7);
    const keyHash = createHash("sha256").update(plaintext).digest("hex");

    let rows: ApiKey[] = [];
    try {
      rows = (await query<ApiKey>(
        'SELECT id, role, label, expires_at AS "expiresAt" FROM api_keys WHERE key_hash = $1',
        [keyHash],
      )) ?? [];
    } catch {
      rows = [];
    }

    if (!rows || rows.length === 0) {
      logger.info({
        event: "auth_attempt",
        success: false,
        ip,
        keyLabel: null,
        path: req.path,
        method: req.method,
        reason: "key_not_found",
      });
      res.status(403).json({ error: "Forbidden", message: "Invalid API key" });
      return;
    }

    const apiKey = rows[0];

    if (apiKey.expiresAt && apiKey.expiresAt.getTime() <= Date.now()) {
      logger.info({
        event: "auth_attempt",
        success: false,
        ip,
        keyLabel: apiKey.label,
        path: req.path,
        method: req.method,
        reason: "expired",
      });
      res.status(401).json({ error: "Unauthorized", message: "API key has expired" });
      return;
    }

    if (options?.role && apiKey.role !== options.role) {
      logger.info({
        event: "auth_attempt",
        success: false,
        ip,
        keyLabel: apiKey.label,
        path: req.path,
        method: req.method,
        reason: "insufficient_permissions",
      });
      res.status(403).json({ error: "Forbidden", message: "Insufficient permissions" });
      return;
    }

    if (options?.minRole === "readonly" && apiKey.role !== "admin") {
      if (apiKey.role !== "readonly" || !READ_ONLY_METHODS.has(req.method)) {
        logger.info({
          event: "auth_attempt",
          success: false,
          ip,
          keyLabel: apiKey.label,
          path: req.path,
          method: req.method,
          reason: "insufficient_permissions",
        });
        res.status(403).json({ error: "Forbidden", message: "Insufficient permissions" });
        return;
      }
    }

    logger.info({
      event: "auth_attempt",
      success: true,
      ip,
      keyLabel: apiKey.label,
      path: req.path,
      method: req.method,
    });

    req.apiKey = apiKey;
    next();
  };
}
