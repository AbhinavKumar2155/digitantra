import { createHash } from "node:crypto";

import { config } from "dotenv";
import { NextRequest } from "next/server";

import { POST as logoutPost } from "../src/app/api/email-auth/logout/route";
import { POST as requestOtpPost } from "../src/app/api/email-auth/request-otp/route";
import { GET as getSession } from "../src/app/api/email-auth/session/route";
import { POST as verifyOtpPost } from "../src/app/api/email-auth/verify-otp/route";
import { EMAIL_AUTH_SESSION_COOKIE_NAME } from "../src/lib/email-auth/shared";
import { ensureSchema, getPool } from "../src/lib/db";

config({ path: ".env.local" });

type OtpRow = {
  email_lower: string;
  mode: "login" | "signup";
  otp_hash: Buffer;
  created_at: Date;
};

function createOtpHash(emailLower: string, otpCode: string) {
  const secret = process.env.EMAIL_AUTH_SECRET?.trim() || process.env.NEXTAUTH_SECRET?.trim();

  if (!secret) {
    throw new Error("EMAIL_AUTH_SECRET or NEXTAUTH_SECRET is required.");
  }

  return createHash("sha256")
    .update(`otp:${secret}:${emailLower}:${otpCode}`)
    .digest();
}

function deriveOtpCode(emailLower: string, otpHash: Buffer) {
  for (let index = 0; index < 1_000_000; index += 1) {
    const otpCode = index.toString().padStart(6, "0");
    const candidateHash = createOtpHash(emailLower, otpCode);

    if (candidateHash.equals(otpHash)) {
      return otpCode;
    }
  }

  throw new Error("Unable to derive OTP code from stored hash.");
}

async function main() {
  const email = `digitantra.helpdesk+e2e-${Date.now()}@gmail.com`;
  await ensureSchema();
  const pool = getPool();

  async function runOtpCycle(mode: "signup" | "login") {
    const requestOtpResponse = await requestOtpPost(
      new NextRequest("http://localhost:9002/api/email-auth/request-otp", {
        method: "POST",
        body: JSON.stringify({
          email,
          mode,
        }),
        headers: {
          "content-type": "application/json",
        },
      })
    );

    const requestOtpPayload = await requestOtpResponse.json();

    if (!requestOtpResponse.ok) {
      throw new Error(`${mode} OTP request failed: ${JSON.stringify(requestOtpPayload)}`);
    }

    const otpResult = await pool.query<OtpRow>(
      `SELECT email_lower, mode, otp_hash, created_at
       FROM auth_email_otps
       WHERE email_lower = $1 AND mode = $2 AND consumed_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [email.toLowerCase(), mode]
    );
    const otpRow = otpResult.rows[0];

    if (!otpRow) {
      throw new Error(`${mode} OTP row was not stored in Postgres.`);
    }

    const storedHash =
      Buffer.isBuffer(otpRow.otp_hash)
        ? otpRow.otp_hash
        : Buffer.from(String(otpRow.otp_hash), "hex");
    const otpCode = deriveOtpCode(email.toLowerCase(), storedHash);

    const verifyOtpResponse = await verifyOtpPost(
      new NextRequest("http://localhost:9002/api/email-auth/verify-otp", {
        method: "POST",
        body: JSON.stringify({
          email,
          otp: otpCode,
          mode,
        }),
        headers: {
          "content-type": "application/json",
        },
      })
    );

    const verifyOtpPayload = await verifyOtpResponse.json();

    if (!verifyOtpResponse.ok) {
      throw new Error(`${mode} OTP verification failed: ${JSON.stringify(verifyOtpPayload)}`);
    }

    const setCookieHeader = verifyOtpResponse.headers.get("set-cookie");

    if (!setCookieHeader) {
      throw new Error(`${mode} verification did not issue a session cookie.`);
    }

    const cookiePair = setCookieHeader.split(";")[0];
    const [cookieName, cookieValue] = cookiePair.split("=");

    if (cookieName !== EMAIL_AUTH_SESSION_COOKIE_NAME || !cookieValue) {
      throw new Error(`Unexpected session cookie header for ${mode}: ${setCookieHeader}`);
    }

    const sessionResponse = await getSession(
      new NextRequest("http://localhost:9002/api/email-auth/session", {
        headers: {
          cookie: `${EMAIL_AUTH_SESSION_COOKIE_NAME}=${cookieValue}`,
        },
      })
    );

    const sessionPayload = await sessionResponse.json();

    if (!sessionResponse.ok || !sessionPayload.authenticated) {
      throw new Error(`${mode} session lookup failed: ${JSON.stringify(sessionPayload)}`);
    }

    return {
      requestOtpPayload,
      verifyOtpPayload,
      sessionPayload,
      sessionCookie: `${EMAIL_AUTH_SESSION_COOKIE_NAME}=${cookieValue}`,
      otpCode,
    };
  }

  const signupResult = await runOtpCycle("signup");

  const logoutResponse = await logoutPost(
    new NextRequest("http://localhost:9002/api/email-auth/logout", {
      method: "POST",
      headers: {
        cookie: signupResult.sessionCookie,
      },
    })
  );

  const logoutPayload = await logoutResponse.json();

  if (!logoutResponse.ok) {
    throw new Error(`Logout failed: ${JSON.stringify(logoutPayload)}`);
  }

  const postLogoutSessionResponse = await getSession(
    new NextRequest("http://localhost:9002/api/email-auth/session", {
      headers: {
        cookie: signupResult.sessionCookie,
      },
    })
  );

  const postLogoutSessionPayload = await postLogoutSessionResponse.json();

  if (!postLogoutSessionResponse.ok || postLogoutSessionPayload.authenticated) {
    throw new Error(`Session still active after logout: ${JSON.stringify(postLogoutSessionPayload)}`);
  }

  const loginResult = await runOtpCycle("login");

  console.log(
    JSON.stringify(
      {
        ok: true,
        email,
        signup: {
          otpCode: signupResult.otpCode,
          otpExpiresAt: signupResult.requestOtpPayload.expiresAt,
          verifiedUser: signupResult.verifyOtpPayload.user,
          sessionUser: signupResult.sessionPayload.user,
        },
        logout: logoutPayload,
        login: {
          otpCode: loginResult.otpCode,
          otpExpiresAt: loginResult.requestOtpPayload.expiresAt,
          verifiedUser: loginResult.verifyOtpPayload.user,
          sessionUser: loginResult.sessionPayload.user,
        },
      },
      null,
      2
    )
  );

  // Clean up the throwaway e2e user so the database stays tidy.
  await pool.query(`DELETE FROM auth_email_users WHERE email_lower = $1`, [
    email.toLowerCase(),
  ]);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
