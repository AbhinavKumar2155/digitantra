import { neon } from "@neondatabase/serverless";
import { Pool as PgPool } from "pg";

type PoolLike = {
  query<T = Record<string, unknown>>(
    text: string,
    values?: unknown[]
  ): Promise<{ rows: T[] }>;
  end?: () => Promise<void>;
};

const globalForDb = globalThis as typeof globalThis & {
  __digitantraDbPool__?: PoolLike;
  __digitantraDbPoolKind__?: "neon-http" | "pg";
  __digitantraSchemaPromise__?: Promise<void>;
};

function getDatabaseUrl() {
  const url = process.env.DATABASE_URL?.trim();

  if (!url) {
    throw new Error("DATABASE_URL is not configured.");
  }

  return url;
}

/**
 * Primary: Neon's stateless HTTP driver. Every query is a single HTTPS request
 * on port 443, so it works in networks where outbound TCP 5432 is firewalled.
 * Fallback: node-postgres, enabled with DIGITANTRA_DB_FORCE_PG=1 (uses direct
 * TCP to the database and benefits from connection pooling when reachable).
 */
function createNeonHttpPool(): PoolLike {
  const sql = neon(getDatabaseUrl());

  return {
    async query<T = Record<string, unknown>>(text: string, values: unknown[] = []) {
      // The HTTP transport JSON-serializes parameters, so normalize anything
      // that is not a plain string/number/boolean (e.g. Date objects).
      const serialized = values.map((value) =>
        value instanceof Date ? value.toISOString() : value
      );
      const rows = await sql.query(text, serialized);

      return { rows: rows as T[] };
    },
  };
}

function createPgPool(): PoolLike {
  const pool = new PgPool({
    connectionString: getDatabaseUrl(),
    ssl: { rejectUnauthorized: false },
    max: 5,
    application_name: "DigiTantra",
  });

  return {
    query: async <T = Record<string, unknown>>(text: string, values?: unknown[]) => {
      const result = await pool.query(text, values);

      return { rows: result.rows as T[] };
    },
    end: () => pool.end(),
  };
}

export function getPool(): PoolLike {
  if (!globalForDb.__digitantraDbPool__) {
    if (process.env.DIGITANTRA_DB_FORCE_PG === "1") {
      globalForDb.__digitantraDbPool__ = createPgPool();
      globalForDb.__digitantraDbPoolKind__ = "pg";
    } else {
      globalForDb.__digitantraDbPool__ = createNeonHttpPool();
      globalForDb.__digitantraDbPoolKind__ = "neon-http";
    }
  }

  return globalForDb.__digitantraDbPool__;
}

export function resetDbPool() {
  const pool = globalForDb.__digitantraDbPool__;

  pool?.end?.().catch(() => undefined);
  globalForDb.__digitantraDbPool__ = undefined;
  globalForDb.__digitantraDbPoolKind__ = undefined;
}

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS auth_email_users (
     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
     email text NOT NULL,
     email_lower text NOT NULL UNIQUE,
     name text,
     image text,
     password_hash text,
     password_salt text,
     email_verified_at timestamptz,
     created_at timestamptz NOT NULL DEFAULT now(),
     last_login_at timestamptz
   )`,
  `CREATE TABLE IF NOT EXISTS auth_email_otps (
     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
     email text NOT NULL,
     email_lower text NOT NULL,
     mode text NOT NULL,
     otp_hash text NOT NULL,
     created_at timestamptz NOT NULL DEFAULT now(),
     expires_at timestamptz NOT NULL,
     attempts integer NOT NULL DEFAULT 0,
     consumed_at timestamptz,
     signup_payload jsonb
   )`,
  `CREATE INDEX IF NOT EXISTS auth_email_otps_email_mode_created_idx
     ON auth_email_otps (email_lower, mode, created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS auth_email_sessions (
     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
     token_hash text NOT NULL UNIQUE,
     user_id uuid NOT NULL REFERENCES auth_email_users (id) ON DELETE CASCADE,
     email text NOT NULL,
     email_lower text NOT NULL,
     created_at timestamptz NOT NULL DEFAULT now(),
     expires_at timestamptz NOT NULL,
     last_seen_at timestamptz NOT NULL DEFAULT now()
   )`,
  `CREATE INDEX IF NOT EXISTS auth_email_sessions_user_idx
     ON auth_email_sessions (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_oauth_users (
     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
     email text NOT NULL,
     email_lower text NOT NULL UNIQUE,
     name text,
     image text,
     providers text[] NOT NULL DEFAULT '{}',
     created_at timestamptz NOT NULL DEFAULT now(),
     last_login_at timestamptz
   )`,
  `CREATE TABLE IF NOT EXISTS api_rate_limits (
     key text PRIMARY KEY,
     client_hash text NOT NULL,
     route_id text NOT NULL,
     scope text NOT NULL,
     count integer NOT NULL,
     window_start timestamptz NOT NULL,
     created_at timestamptz NOT NULL DEFAULT now(),
     updated_at timestamptz NOT NULL DEFAULT now(),
     expires_at timestamptz NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS course_marketplace (
     id text PRIMARY KEY,
     catalog jsonb NOT NULL,
     updated_at timestamptz NOT NULL DEFAULT now()
   )`,
];

async function runSchemaStatements() {
  const pool = getPool();

  for (const statement of SCHEMA_STATEMENTS) {
    await pool.query(statement);
  }

  // Housekeeping: drop long-expired auth rows (replaces MongoDB TTL indexes).
  await pool.query(
    `DELETE FROM auth_email_otps WHERE expires_at < now() - interval '1 day'`
  );
  await pool.query(
    `DELETE FROM auth_email_sessions WHERE expires_at < now() - interval '1 day'`
  );
  await pool.query(
    `DELETE FROM api_rate_limits WHERE expires_at < now() - interval '1 day'`
  );
}

export function ensureSchema(): Promise<void> {
  if (!globalForDb.__digitantraSchemaPromise__) {
    globalForDb.__digitantraSchemaPromise__ = runSchemaStatements().catch((error) => {
      globalForDb.__digitantraSchemaPromise__ = undefined;
      throw error;
    });
  }

  return globalForDb.__digitantraSchemaPromise__;
}
