import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";

import { authOptions, OAUTH_USERS_TABLE } from "@/lib/auth";
import { EmailAuthApiError, getEmailAuthUserFromToken } from "@/lib/email-auth/server";
import { EMAIL_AUTH_SESSION_COOKIE_NAME } from "@/lib/email-auth/shared";
import { ensureSchema, getPool } from "@/lib/db";
import { enforceApiRateLimit } from "@/lib/security/api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type OAuthUserRow = {
  id: string;
  email: string;
  email_lower: string;
  name: string | null;
  image: string | null;
  created_at: string;
  last_login_at: string | null;
};

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

async function getOrCreateOAuthUser(sessionEmail: string) {
  await ensureSchema();
  const pool = getPool();
  const emailLower = normalizeEmail(sessionEmail);

  await pool.query(
    `INSERT INTO ${OAUTH_USERS_TABLE} (email, email_lower, last_login_at)
     VALUES ($1, $2, now())
     ON CONFLICT (email_lower) DO UPDATE SET
       email = EXCLUDED.email,
       last_login_at = now()`,
    [sessionEmail, emailLower]
  );

  const result = await pool.query<OAuthUserRow>(
    `SELECT id, email, email_lower, name, image,
            created_at::text AS created_at, last_login_at::text AS last_login_at
     FROM ${OAUTH_USERS_TABLE} WHERE email_lower = $1`,
    [emailLower]
  );

  return result.rows[0] ?? null;
}

function toOAuthApiUser(user: OAuthUserRow) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    image: user.image,
    provider: "google-oauth",
    emailVerifiedAt: null,
    createdAt: new Date(user.created_at).toISOString(),
    lastLoginAt: user.last_login_at
      ? new Date(user.last_login_at).toISOString()
      : null,
  };
}

export async function GET(request: NextRequest) {
  const blockedResponse = await enforceApiRateLimit(request, {
    routeId: "email-auth/session",
  });

  if (blockedResponse) {
    return blockedResponse;
  }

  try {
    const sessionToken =
      request.cookies.get(EMAIL_AUTH_SESSION_COOKIE_NAME)?.value ?? null;
    const user = await getEmailAuthUserFromToken(sessionToken);

    if (user) {
      return NextResponse.json({
        authenticated: true,
        user,
      });
    }

    const oauthSession = await getServerSession(authOptions);
    const sessionEmail = oauthSession?.user?.email?.trim();

    if (!sessionEmail) {
      return NextResponse.json({
        authenticated: false,
        user: null,
      });
    }

    const oauthUser = await getOrCreateOAuthUser(sessionEmail);

    if (!oauthUser) {
      return NextResponse.json(
        {
          authenticated: false,
          user: null,
          error: "Unable to read the OAuth session right now.",
        },
        { status: 503 }
      );
    }

    return NextResponse.json({
      authenticated: true,
      user: toOAuthApiUser(oauthUser),
    });
  } catch (error) {
    if (error instanceof EmailAuthApiError) {
      return NextResponse.json(
        {
          authenticated: false,
          user: null,
          error: error.message,
        },
        { status: error.status }
      );
    }

    console.error("email-auth session error", error);
    return NextResponse.json(
      {
        authenticated: false,
        user: null,
        error: "Unable to read the email auth session right now.",
      },
      { status: 503 }
    );
  }
}
