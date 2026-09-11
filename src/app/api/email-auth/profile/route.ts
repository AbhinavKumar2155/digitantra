import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { z } from "zod";

import { authOptions, OAUTH_USERS_TABLE } from "@/lib/auth";
import {
  EmailAuthApiError,
  getEmailAuthUserFromToken,
  updateEmailAuthProfile,
} from "@/lib/email-auth/server";
import { EMAIL_AUTH_SESSION_COOKIE_NAME } from "@/lib/email-auth/shared";
import { ensureSchema, getPool } from "@/lib/db";
import {
  enforceApiRateLimit,
  getJsonMaxBytes,
  isApiPayloadError,
  parseJsonBody,
} from "@/lib/security/api";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const MAX_PROFILE_IMAGE_BYTES = 1_500_000;

const updateProfileSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "Name must be at least 2 characters long.")
    .max(80, "Name must be 80 characters or fewer.")
    .optional(),
  image: z
    .string()
    .max(2_200_000, "Profile photo payload is too large.")
    .regex(
      /^data:image\/(?:png|jpeg|jpg|webp|gif);base64,[a-z0-9+/=]+$/i,
      "Profile photo must be a valid PNG, JPG, WEBP, or GIF image."
    )
    .nullable()
    .optional(),
}).strict();

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

function normalizeOAuthProfileImageDataUrl(value: string | null | undefined) {
  if (!value) {
    return null;
  }

  const normalized = value.trim();

  if (!normalized) {
    return null;
  }

  const match = normalized.match(
    /^data:image\/(?:png|jpeg|jpg|webp|gif);base64,([a-z0-9+/=]+)$/i
  );

  if (!match) {
    throw new EmailAuthApiError(
      "Profile photo must be a valid PNG, JPG, WEBP, or GIF image.",
      400
    );
  }

  const decoded = Buffer.from(match[1], "base64");

  if (!decoded.length || decoded.length > MAX_PROFILE_IMAGE_BYTES) {
    throw new EmailAuthApiError("Profile photo must be 1.5 MB or smaller.", 400);
  }

  return normalized;
}

async function getOAuthSessionEmail() {
  const oauthSession = await getServerSession(authOptions);
  const sessionEmail = oauthSession?.user?.email?.trim();

  if (!sessionEmail) {
    return null;
  }

  return sessionEmail;
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
    lastLoginAt: user.last_login_at ? new Date(user.last_login_at).toISOString() : null,
  };
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

async function updateOAuthProfile({
  email,
  name,
  image,
}: {
  email: string;
  name?: string;
  image?: string | null;
}) {
  await ensureSchema();
  const pool = getPool();
  const emailLower = normalizeEmail(email);

  const updates: { name?: string; image?: string | null } = {};

  if (typeof name !== "undefined") {
    updates.name = name.trim();
  }

  if (typeof image !== "undefined") {
    updates.image = normalizeOAuthProfileImageDataUrl(image);
  }

  if (!Object.keys(updates).length) {
    throw new EmailAuthApiError("No profile changes were provided.", 400);
  }

  await pool.query(
    `INSERT INTO ${OAUTH_USERS_TABLE} (email, email_lower, name, image, last_login_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (email_lower) DO UPDATE SET
       email = EXCLUDED.email,
       name = COALESCE(EXCLUDED.name, ${OAUTH_USERS_TABLE}.name),
       image = COALESCE(EXCLUDED.image, ${OAUTH_USERS_TABLE}.image),
       last_login_at = now()`,
    [email, emailLower, updates.name ?? null, updates.image ?? null]
  );

  const result = await pool.query<OAuthUserRow>(
    `SELECT id, email, email_lower, name, image,
            created_at::text AS created_at, last_login_at::text AS last_login_at
     FROM ${OAUTH_USERS_TABLE} WHERE email_lower = $1`,
    [emailLower]
  );

  return result.rows[0] ?? null;
}

export async function GET(request: NextRequest) {
  const blockedResponse = await enforceApiRateLimit(request, {
    routeId: "email-auth/profile:get",
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

    const sessionEmail = await getOAuthSessionEmail();

    if (!sessionEmail) {
      return NextResponse.json(
        {
          authenticated: false,
          user: null,
        },
        { status: 401 }
      );
    }

    const oauthUser = await getOrCreateOAuthUser(sessionEmail);

    if (!oauthUser) {
      return NextResponse.json(
        { authenticated: false, user: null, error: "Unable to load profile right now." },
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

    console.error("email-auth profile get error", error);
    return NextResponse.json(
      { authenticated: false, user: null, error: "Unable to load profile right now." },
      { status: 503 }
    );
  }
}

export async function PATCH(request: NextRequest) {
  const blockedResponse = await enforceApiRateLimit(request, {
    routeId: "email-auth/profile:patch",
  });

  if (blockedResponse) {
    return blockedResponse;
  }

  try {
    const sessionToken =
      request.cookies.get(EMAIL_AUTH_SESSION_COOKIE_NAME)?.value ?? null;
    const body = await parseJsonBody(request, updateProfileSchema, {
      maxBytes: getJsonMaxBytes("auth"),
      oversizeMessage: "Profile update payload is too large.",
    });

    const emailSessionUser = await getEmailAuthUserFromToken(sessionToken);
    if (emailSessionUser) {
      const user = await updateEmailAuthProfile({
        sessionToken,
        name: body.name,
        image: body.image,
      });

      return NextResponse.json({
        ok: true,
        user,
      });
    }

    const sessionEmail = await getOAuthSessionEmail();

    if (!sessionEmail) {
      throw new EmailAuthApiError("You must be logged in to update profile.", 401);
    }

    const updatedOAuthUser = await updateOAuthProfile({
      email: sessionEmail,
      name: body.name,
      image: body.image,
    });

    if (!updatedOAuthUser) {
      throw new EmailAuthApiError("Unable to update profile right now.", 503);
    }

    return NextResponse.json({
      ok: true,
      user: toOAuthApiUser(updatedOAuthUser),
    });
  } catch (error) {
    if (isApiPayloadError(error)) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.issues[0]?.message ?? "Invalid profile update request." },
        { status: 400 }
      );
    }

    if (error instanceof EmailAuthApiError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }

    console.error("email-auth profile patch error", error);
    return NextResponse.json(
      { error: "Unable to update profile right now. Please try again." },
      { status: 500 }
    );
  }
}
