import {
  createHash,
  randomBytes,
  randomInt,
  randomUUID,
  scrypt,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

import nodemailer, { type Transporter } from "nodemailer";

import { ensureSchema, getPool } from "@/lib/db";
import {
  EMAIL_AUTH_OTP_LENGTH,
  EMAIL_AUTH_SESSION_COOKIE_NAME,
  type EmailAuthOtpMode,
  type EmailAuthUser,
} from "@/lib/email-auth/shared";

const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_REQUEST_COOLDOWN_MS = 30 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PASSWORD_HASH_KEYLEN = 64;
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;
const MAX_PROFILE_IMAGE_BYTES = 1_500_000;

const scryptAsync = promisify(scrypt);

/**
 * Raw database row shape. The Neon HTTP transport returns timestamps as ISO
 * strings and hashes as hex text, so these fields are normalized through the
 * rowTo* mappers before any logic touches them.
 */
type EmailAuthUserRow = {
  id: string;
  email: string;
  email_lower: string;
  name: string | null;
  image: string | null;
  password_hash: unknown;
  password_salt: unknown;
  email_verified_at: unknown;
  created_at: unknown;
  last_login_at: unknown;
};

type SignupOtpPayload = {
  name: string;
  image: string | null;
  passwordHash: Buffer;
  passwordSalt: Buffer;
};

type EmailAuthOtpRow = {
  id: string;
  email: string;
  email_lower: string;
  mode: EmailAuthOtpMode;
  otp_hash: unknown;
  created_at: unknown;
  expires_at: unknown;
  attempts: number;
  consumed_at: unknown;
  signup_payload: unknown;
};

type EmailAuthSessionRow = {
  id: string;
  token_hash: unknown;
  user_id: string;
  email: string;
  email_lower: string;
  created_at: unknown;
  expires_at: unknown;
  last_seen_at: unknown;
};

/** Normalized in-memory view of a row (Buffer hashes, Date timestamps). */
type EmailAuthUserDocument = {
  _id: string;
  email: string;
  emailLower: string;
  name: string | null;
  image: string | null;
  passwordHash: Buffer | null;
  passwordSalt: Buffer | null;
  emailVerifiedAt: Date | null;
  createdAt: Date;
  lastLoginAt: Date | null;
};

type EmailAuthOtpDocument = {
  id: string;
  email: string;
  emailLower: string;
  mode: EmailAuthOtpMode;
  otpHash: Buffer;
  createdAt: Date;
  expiresAt: Date;
  attempts: number;
  consumedAt: Date | null;
  signupPayload: SignupOtpPayload | null;
};

type EmailAuthSessionDocument = {
  id: string;
  tokenHash: Buffer;
  userId: string;
  email: string;
  emailLower: string;
  createdAt: Date;
  expiresAt: Date;
  lastSeenAt: Date;
};

type GlobalEmailAuthState = typeof globalThis & {
  __digitantraSmtpTransporter__?: Transporter;
};

const globalForEmailAuth = globalThis as GlobalEmailAuthState;

export class EmailAuthApiError extends Error {
  status: number;

  constructor(message: string, status = 400) {
    super(message);
    this.name = "EmailAuthApiError";
    this.status = status;
  }
}

function asDate(value: unknown): Date | null {
  if (value instanceof Date) {
    return value;
  }

  if (typeof value === "string" || typeof value === "number") {
    const date = new Date(value);

    return Number.isNaN(date.getTime()) ? null : date;
  }

  return null;
}

function asBuffer(value: unknown): Buffer | null {
  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (typeof value === "string") {
    return Buffer.from(value, "hex");
  }

  return null;
}

function toHex(value: Buffer) {
  return value.toString("hex");
}

function rowToUserDocument(row: EmailAuthUserRow): EmailAuthUserDocument {
  return {
    _id: row.id,
    email: row.email,
    emailLower: row.email_lower,
    name: row.name,
    image: row.image,
    passwordHash: asBuffer(row.password_hash),
    passwordSalt: asBuffer(row.password_salt),
    emailVerifiedAt: asDate(row.email_verified_at),
    createdAt: asDate(row.created_at) ?? new Date(0),
    lastLoginAt: asDate(row.last_login_at),
  };
}

function rowToOtpDocument(row: EmailAuthOtpRow): EmailAuthOtpDocument {
  return {
    id: row.id,
    email: row.email,
    emailLower: row.email_lower,
    mode: row.mode,
    otpHash: asBuffer(row.otp_hash) ?? Buffer.alloc(0),
    createdAt: asDate(row.created_at) ?? new Date(0),
    expiresAt: asDate(row.expires_at) ?? new Date(0),
    attempts: row.attempts,
    consumedAt: asDate(row.consumed_at),
    signupPayload: normalizeSignupPayload(row.signup_payload),
  };
}

function rowToSessionDocument(row: EmailAuthSessionRow): EmailAuthSessionDocument {
  return {
    id: row.id,
    tokenHash: asBuffer(row.token_hash) ?? Buffer.alloc(0),
    userId: row.user_id,
    email: row.email,
    emailLower: row.email_lower,
    createdAt: asDate(row.created_at) ?? new Date(0),
    expiresAt: asDate(row.expires_at) ?? new Date(0),
    lastSeenAt: asDate(row.last_seen_at) ?? new Date(0),
  };
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function normalizeDisplayName(value: string) {
  const normalized = value.trim().replace(/\s+/g, " ");

  if (normalized.length < 2) {
    throw new EmailAuthApiError("Name must be at least 2 characters long.", 400);
  }

  if (normalized.length > 80) {
    throw new EmailAuthApiError("Name must be 80 characters or fewer.", 400);
  }

  return normalized;
}

function validatePasswordForSignup(password: string) {
  if (password.length < PASSWORD_MIN_LENGTH) {
    throw new EmailAuthApiError(
      `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`,
      400
    );
  }

  if (password.length > PASSWORD_MAX_LENGTH) {
    throw new EmailAuthApiError("Password is too long.", 400);
  }

  if (!/[a-z]/.test(password)) {
    throw new EmailAuthApiError(
      "Password must include at least one lowercase letter.",
      400
    );
  }

  if (!/[A-Z]/.test(password)) {
    throw new EmailAuthApiError(
      "Password must include at least one uppercase letter.",
      400
    );
  }

  if (!/\d/.test(password)) {
    throw new EmailAuthApiError(
      "Password must include at least one number.",
      400
    );
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    throw new EmailAuthApiError(
      "Password must include at least one special character.",
      400
    );
  }

  return password;
}

function validatePasswordForLogin(password: string) {
  if (!password || !password.trim()) {
    throw new EmailAuthApiError("Password is required.", 400);
  }

  if (password.length > PASSWORD_MAX_LENGTH) {
    throw new EmailAuthApiError("Password is too long.", 400);
  }

  return password;
}

function normalizeProfileImageDataUrl(value: string | null | undefined) {
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

function getEmailAuthSecret() {
  const secret =
    process.env.EMAIL_AUTH_SECRET?.trim() || process.env.NEXTAUTH_SECRET?.trim();

  if (!secret) {
    throw new EmailAuthApiError("EMAIL_AUTH_SECRET is not configured.", 500);
  }

  return secret;
}

function createScopedHash(scope: "otp" | "session", value: string) {
  return createHash("sha256")
    .update(`${scope}:${getEmailAuthSecret()}:${value}`)
    .digest();
}

function hashesMatch(expectedHash: Buffer, candidateHash: Buffer) {
  if (expectedHash.length !== candidateHash.length) {
    return false;
  }

  return timingSafeEqual(expectedHash, candidateHash);
}

async function derivePasswordHash(password: string, salt: Buffer) {
  return (await scryptAsync(password, salt, PASSWORD_HASH_KEYLEN)) as Buffer;
}

async function createPasswordHash(password: string) {
  const passwordSalt = randomBytes(16);
  const passwordHash = await derivePasswordHash(password, passwordSalt);

  return {
    passwordHash,
    passwordSalt,
  };
}

async function passwordMatches(
  password: string,
  expectedHash: Buffer | null,
  expectedSalt: Buffer | null
) {
  if (!expectedHash || !expectedSalt) {
    return false;
  }

  const candidateHash = await derivePasswordHash(password, expectedSalt);

  return hashesMatch(expectedHash, candidateHash);
}

function createOtpCode() {
  return randomInt(0, 10 ** EMAIL_AUTH_OTP_LENGTH)
    .toString()
    .padStart(EMAIL_AUTH_OTP_LENGTH, "0");
}

function toEmailAuthUser(user: EmailAuthUserDocument): EmailAuthUser {
  return {
    id: user._id,
    email: user.email,
    name: user.name,
    image: user.image,
    provider: "email-password",
    emailVerifiedAt: user.emailVerifiedAt?.toISOString() ?? null,
    createdAt: user.createdAt.toISOString(),
    lastLoginAt: user.lastLoginAt?.toISOString() ?? null,
  };
}

function normalizeSignupPayload(value: unknown): SignupOtpPayload | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const payload = value as {
    name?: unknown;
    image?: unknown;
    passwordHash?: unknown;
    passwordSalt?: unknown;
  };
  const toBuffer = (input: unknown) => {
    if (Buffer.isBuffer(input)) {
      return input;
    }

    if (typeof input === "string") {
      return Buffer.from(input, "base64");
    }

    return null;
  };
  const passwordHash = toBuffer(payload.passwordHash);
  const passwordSalt = toBuffer(payload.passwordSalt);

  if (!passwordHash || !passwordSalt || typeof payload.name !== "string") {
    return null;
  }

  return {
    name: payload.name,
    image: typeof payload.image === "string" ? payload.image : null,
    passwordHash,
    passwordSalt,
  };
}

function getSmtpTransporter() {
  const host = process.env.SMTP_HOST?.trim();
  const portRaw = process.env.SMTP_PORT?.trim();
  const user = process.env.SMTP_USER?.trim();
  const pass = process.env.SMTP_PASSWORD?.trim();

  if (!host || !portRaw || !user || !pass) {
    throw new EmailAuthApiError(
      "Email OTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and AUTH_OTP_FROM_EMAIL.",
      500
    );
  }

  if (!globalForEmailAuth.__digitantraSmtpTransporter__) {
    const port = Number(portRaw);
    globalForEmailAuth.__digitantraSmtpTransporter__ = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: {
        user,
        pass,
      },
    });
  }

  return globalForEmailAuth.__digitantraSmtpTransporter__;
}

async function getUserByEmail(emailLower: string) {
  await ensureSchema();
  const pool = getPool();
  const result = await pool.query<EmailAuthUserRow>(
    `SELECT * FROM auth_email_users WHERE email_lower = $1`,
    [emailLower]
  );

  const row = result.rows[0];

  return row ? rowToUserDocument(row) : null;
}

async function sendOtpEmail({
  email,
  otpCode,
  mode,
}: {
  email: string;
  otpCode: string;
  mode: EmailAuthOtpMode;
}) {
  const transporter = getSmtpTransporter();
  const fromEmail = process.env.AUTH_OTP_FROM_EMAIL?.trim();
  const companyName = process.env.AUTH_COMPANY_NAME?.trim() || "DigiTantra";
  const fromName = process.env.AUTH_OTP_FROM_NAME?.trim() || companyName;
  const supportEmail = process.env.AUTH_SUPPORT_EMAIL?.trim() || fromEmail;
  const companyAddress =
    process.env.AUTH_COMPANY_ADDRESS?.trim() || "Jalandhar, Punjab, India";
  const supportUrl = "https://digitantra.vercel.app";

  if (!fromEmail) {
    throw new EmailAuthApiError("AUTH_OTP_FROM_EMAIL is not configured.", 500);
  }

  const isPasswordReset = mode === "password-reset";
  const subject = isPasswordReset
    ? `${companyName} password reset code • Expires in 10 minutes`
    : `${companyName} sign-up verification code • Expires in 10 minutes`;
  const actionLabel = isPasswordReset ? "reset your password" : "complete sign up";
  const plainTextLines = [
    `${companyName} verification`,
    "",
    `Your verification code is ${otpCode}.`,
    `Use this code to ${actionLabel} to DigiTantra.`,
    "This code expires in 10 minutes.",
    "",
    `If you did not request this email, you can ignore it safely.`,
    "",
    `${companyName}`,
    companyAddress,
    supportEmail ? `Support: ${supportEmail}` : null,
    supportUrl ? `Website: ${supportUrl}` : null,
  ].filter(Boolean);

  await transporter.sendMail({
    from: `"${fromName}" <${fromEmail}>`,
    to: email,
    subject,
    text: plainTextLines.join("\n"),
    html: `
      <div style="font-family: Inter, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; color: #e5e7eb; background: #0b1020; border: 1px solid rgba(139,92,246,0.24); border-radius: 20px;">
        <div style="font-size: 13px; letter-spacing: 0.16em; text-transform: uppercase; color: #a78bfa; margin-bottom: 12px;">${companyName} Security</div>
        <h1 style="font-size: 28px; line-height: 1.2; color: #ffffff; margin: 0 0 12px;">Your verification code</h1>
        <p style="font-size: 16px; line-height: 1.7; color: #cbd5e1; margin: 0 0 24px;">
          Use the code below to ${actionLabel} to ${companyName}. This code stays valid for 10 minutes.
        </p>
        <div style="font-size: 36px; font-weight: 700; letter-spacing: 0.4em; color: #8b5cf6; background: rgba(139,92,246,0.1); border: 1px solid rgba(139,92,246,0.24); border-radius: 18px; padding: 20px 24px; text-align: center; margin: 0 0 24px;">
          ${otpCode}
        </div>
        <p style="font-size: 14px; line-height: 1.7; color: #94a3b8; margin: 0 0 20px;">
          If you did not request this code, you can safely ignore this email.
        </p>
        <div style="border-top: 1px solid rgba(148,163,184,0.16); padding-top: 18px; margin-top: 18px;">
          <div style="font-size: 15px; font-weight: 600; color: #ffffff; margin-bottom: 8px;">${companyName}</div>
          <p style="font-size: 13px; line-height: 1.7; color: #94a3b8; margin: 0;">
            ${companyAddress}<br />
            ${supportEmail ? `Support: <a href="mailto:${supportEmail}" style="color: #c4b5fd; text-decoration: none;">${supportEmail}</a><br />` : ""}
            ${supportUrl ? `Website: <a href="${supportUrl}" style="color: #c4b5fd; text-decoration: none;">${supportUrl}</a>` : ""}
          </p>
        </div>
      </div>
    `,
  });
}

async function assertSignupAccess(emailLower: string) {
  const user = await getUserByEmail(emailLower);

  if (user?.passwordHash && user?.passwordSalt) {
    throw new EmailAuthApiError(
      "An account already exists for this email. Use Log in instead.",
      409
    );
  }

  return user;
}

async function assertLoginAccess(emailLower: string) {
  const user = await getUserByEmail(emailLower);

  if (!user) {
    throw new EmailAuthApiError(
      "No DigiTantra account exists for this email yet. Use Sign up first.",
      404
    );
  }

  if (!user.passwordHash || !user.passwordSalt) {
    throw new EmailAuthApiError(
      "This account must complete sign up with password and OTP before login.",
      409
    );
  }

  return user;
}

async function assertPasswordResetAccess(emailLower: string) {
  const user = await assertLoginAccess(emailLower);

  if (!user.emailVerifiedAt) {
    throw new EmailAuthApiError(
      "Your account email is not verified yet. Complete sign up first.",
      409
    );
  }

  return user;
}

async function createSessionForUser({
  user,
}: {
  user: EmailAuthUserDocument;
}) {
  await ensureSchema();
  const pool = getPool();
  const issuedAt = new Date();
  const sessionToken = randomBytes(48).toString("hex");
  const sessionExpiresAt = new Date(Date.now() + SESSION_TTL_MS);

  await pool.query(
    `INSERT INTO auth_email_sessions
       (id, token_hash, user_id, email, email_lower, created_at, expires_at, last_seen_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $6)`,
    [
      randomUUID(),
      toHex(createScopedHash("session", sessionToken)),
      user._id,
      user.email,
      user.emailLower,
      issuedAt.toISOString(),
      sessionExpiresAt.toISOString(),
    ]
  );

  return {
    sessionToken,
    sessionExpiresAt,
  };
}

export async function requestEmailOtp({
  email,
  mode,
  signup,
}: {
  email: string;
  mode: "signup";
  signup: {
    name: string;
    password: string;
    image?: string | null;
  };
}) {
  const normalizedEmail = normalizeEmail(email);
  await ensureSchema();
  const pool = getPool();

  await assertSignupAccess(normalizedEmail);

  const signupName = normalizeDisplayName(signup.name);
  const signupPassword = validatePasswordForSignup(signup.password);
  const signupImage = normalizeProfileImageDataUrl(signup.image);
  const { passwordHash, passwordSalt } = await createPasswordHash(signupPassword);

  const mostRecentOtp = await pool.query<EmailAuthOtpRow>(
    `SELECT * FROM auth_email_otps
     WHERE email_lower = $1 AND mode = $2 AND consumed_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC
     LIMIT 1`,
    [normalizedEmail, mode]
  );
  const mostRecentOtpDocument = mostRecentOtp.rows[0]
    ? rowToOtpDocument(mostRecentOtp.rows[0])
    : null;

  if (
    mostRecentOtpDocument &&
    Date.now() - mostRecentOtpDocument.createdAt.getTime() < OTP_REQUEST_COOLDOWN_MS
  ) {
    throw new EmailAuthApiError(
      "A code was just sent. Please wait 30 seconds before requesting another one.",
      429
    );
  }

  const otpCode = createOtpCode();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + OTP_TTL_MS);
  const otpId = randomUUID();

  await pool.query(`DELETE FROM auth_email_otps WHERE email_lower = $1 AND mode = $2`, [
    normalizedEmail,
    mode,
  ]);

  try {
    await pool.query(
      `INSERT INTO auth_email_otps
         (id, email, email_lower, mode, otp_hash, created_at, expires_at, attempts, consumed_at, signup_payload)
       VALUES ($1, $2, $1, $3, $4, $5, $6, 0, NULL, $7::jsonb)`,
      [
        otpId,
        normalizedEmail,
        mode,
        toHex(createScopedHash("otp", `${normalizedEmail}:${otpCode}`)),
        now.toISOString(),
        expiresAt.toISOString(),
        JSON.stringify({
          name: signupName,
          image: signupImage,
          passwordHash: passwordHash.toString("base64"),
          passwordSalt: passwordSalt.toString("base64"),
        }),
      ]
    );

    await sendOtpEmail({ email: normalizedEmail, otpCode, mode });
  } catch (error) {
    await pool.query(`DELETE FROM auth_email_otps WHERE id = $1`, [otpId]);
    throw error;
  }

  return {
    email: normalizedEmail,
    expiresAt: expiresAt.toISOString(),
  };
}

export async function verifyEmailOtp({
  email,
  otp,
  mode,
}: {
  email: string;
  otp: string;
  mode: "signup";
}) {
  const normalizedEmail = normalizeEmail(email);
  await ensureSchema();
  const pool = getPool();

  const existingUser = await assertSignupAccess(normalizedEmail);
  const otpResult = await pool.query<EmailAuthOtpRow>(
    `SELECT * FROM auth_email_otps
     WHERE email_lower = $1 AND mode = $2 AND consumed_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC
     LIMIT 1`,
    [normalizedEmail, mode]
  );
  const otpDocument = otpResult.rows[0] ? rowToOtpDocument(otpResult.rows[0]) : null;

  if (!otpDocument) {
    throw new EmailAuthApiError(
      "This code is no longer valid. Request a new OTP and try again.",
      410
    );
  }

  const providedHash = createScopedHash("otp", `${normalizedEmail}:${otp}`);

  if (!hashesMatch(otpDocument.otpHash, providedHash)) {
    const nextAttempts = otpDocument.attempts + 1;

    await pool.query(
      `UPDATE auth_email_otps
       SET attempts = $2, consumed_at = CASE WHEN $2 >= $3 THEN now() ELSE NULL END
       WHERE id = $1`,
      [otpDocument.id, nextAttempts, OTP_MAX_ATTEMPTS]
    );

    throw new EmailAuthApiError(
      nextAttempts >= OTP_MAX_ATTEMPTS
        ? "Too many incorrect attempts. Request a fresh OTP and try again."
        : "That code is incorrect. Please check the OTP and try again.",
      400
    );
  }

  const signupPayload = otpDocument.signupPayload;

  if (!signupPayload) {
    throw new EmailAuthApiError("Sign-up payload is missing for this OTP.", 500);
  }

  await pool.query(
    `UPDATE auth_email_otps SET consumed_at = now() WHERE id = $1`,
    [otpDocument.id]
  );

  const completedAt = new Date();
  let user: EmailAuthUserDocument;

  if (existingUser) {
    const updatedResult = await pool.query<EmailAuthUserRow>(
      `UPDATE auth_email_users
       SET name = $2, image = $3, password_hash = $4, password_salt = $5,
           email_verified_at = $6, last_login_at = $6
       WHERE id = $1
       RETURNING *`,
      [
        existingUser._id,
        signupPayload.name,
        signupPayload.image,
        toHex(signupPayload.passwordHash),
        toHex(signupPayload.passwordSalt),
        completedAt.toISOString(),
      ]
    );

    user = rowToUserDocument(updatedResult.rows[0]);
  } else {
    const insertedResult = await pool.query<EmailAuthUserRow>(
      `INSERT INTO auth_email_users
         (id, email, email_lower, name, image, password_hash, password_salt,
          email_verified_at, created_at, last_login_at)
       VALUES ($1, $2, $1, $3, $4, $5, $6, $7, $7, $7)
       RETURNING *`,
      [
        randomUUID(),
        normalizedEmail,
        signupPayload.name,
        signupPayload.image,
        toHex(signupPayload.passwordHash),
        toHex(signupPayload.passwordSalt),
        completedAt.toISOString(),
      ]
    );

    user = rowToUserDocument(insertedResult.rows[0]);
  }

  return {
    user: toEmailAuthUser(user),
  };
}

export async function requestPasswordResetOtp({ email }: { email: string }) {
  const normalizedEmail = normalizeEmail(email);
  const mode: EmailAuthOtpMode = "password-reset";
  await ensureSchema();
  const pool = getPool();

  await assertPasswordResetAccess(normalizedEmail);

  const mostRecentOtp = await pool.query<EmailAuthOtpRow>(
    `SELECT * FROM auth_email_otps
     WHERE email_lower = $1 AND mode = $2 AND consumed_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC
     LIMIT 1`,
    [normalizedEmail, mode]
  );
  const mostRecentOtpDocument = mostRecentOtp.rows[0]
    ? rowToOtpDocument(mostRecentOtp.rows[0])
    : null;

  if (
    mostRecentOtpDocument &&
    Date.now() - mostRecentOtpDocument.createdAt.getTime() < OTP_REQUEST_COOLDOWN_MS
  ) {
    throw new EmailAuthApiError(
      "A code was just sent. Please wait 30 seconds before requesting another one.",
      429
    );
  }

  const otpCode = createOtpCode();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + OTP_TTL_MS);
  const otpId = randomUUID();

  await pool.query(`DELETE FROM auth_email_otps WHERE email_lower = $1 AND mode = $2`, [
    normalizedEmail,
    mode,
  ]);

  try {
    await pool.query(
      `INSERT INTO auth_email_otps
         (id, email, email_lower, mode, otp_hash, created_at, expires_at, attempts, consumed_at, signup_payload)
       VALUES ($1, $2, $1, $3, $4, $5, $6, 0, NULL, NULL)`,
      [
        otpId,
        normalizedEmail,
        mode,
        toHex(createScopedHash("otp", `${normalizedEmail}:${otpCode}`)),
        now.toISOString(),
        expiresAt.toISOString(),
      ]
    );

    await sendOtpEmail({ email: normalizedEmail, otpCode, mode });
  } catch (error) {
    await pool.query(`DELETE FROM auth_email_otps WHERE id = $1`, [otpId]);
    throw error;
  }

  return {
    email: normalizedEmail,
    expiresAt: expiresAt.toISOString(),
  };
}

export async function resetPasswordWithOtp({
  email,
  otp,
  newPassword,
}: {
  email: string;
  otp: string;
  newPassword: string;
}) {
  const normalizedEmail = normalizeEmail(email);
  const mode: EmailAuthOtpMode = "password-reset";
  await ensureSchema();
  const pool = getPool();
  const user = await assertPasswordResetAccess(normalizedEmail);
  const password = validatePasswordForSignup(newPassword);

  const otpResult = await pool.query<EmailAuthOtpRow>(
    `SELECT * FROM auth_email_otps
     WHERE email_lower = $1 AND mode = $2 AND consumed_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC
     LIMIT 1`,
    [normalizedEmail, mode]
  );
  const otpDocument = otpResult.rows[0] ? rowToOtpDocument(otpResult.rows[0]) : null;

  if (!otpDocument) {
    throw new EmailAuthApiError(
      "This code is no longer valid. Request a new OTP and try again.",
      410
    );
  }

  const providedHash = createScopedHash("otp", `${normalizedEmail}:${otp}`);

  if (!hashesMatch(otpDocument.otpHash, providedHash)) {
    const nextAttempts = otpDocument.attempts + 1;

    await pool.query(
      `UPDATE auth_email_otps
       SET attempts = $2, consumed_at = CASE WHEN $2 >= $3 THEN now() ELSE NULL END
       WHERE id = $1`,
      [otpDocument.id, nextAttempts, OTP_MAX_ATTEMPTS]
    );

    throw new EmailAuthApiError(
      nextAttempts >= OTP_MAX_ATTEMPTS
        ? "Too many incorrect attempts. Request a fresh OTP and try again."
        : "That code is incorrect. Please check the OTP and try again.",
      400
    );
  }

  await pool.query(
    `UPDATE auth_email_otps SET consumed_at = now() WHERE id = $1`,
    [otpDocument.id]
  );

  const { passwordHash, passwordSalt } = await createPasswordHash(password);

  await pool.query(
    `UPDATE auth_email_users SET password_hash = $2, password_salt = $3 WHERE id = $1`,
    [user._id, toHex(passwordHash), toHex(passwordSalt)]
  );

  // Invalidate every active session after password change.
  await pool.query(`DELETE FROM auth_email_sessions WHERE user_id = $1`, [user._id]);

  return {
    email: normalizedEmail,
  };
}

export async function loginWithEmailPassword({
  email,
  password,
}: {
  email: string;
  password: string;
}) {
  const normalizedEmail = normalizeEmail(email);
  const passwordValue = validatePasswordForLogin(password);
  await ensureSchema();
  const pool = getPool();
  const user = await assertLoginAccess(normalizedEmail);

  const passwordIsValid = await passwordMatches(
    passwordValue,
    user.passwordHash,
    user.passwordSalt
  );

  if (!passwordIsValid) {
    throw new EmailAuthApiError("Invalid email or password.", 401);
  }

  const loginAt = new Date();
  const updatedResult = await pool.query<EmailAuthUserRow>(
    `UPDATE auth_email_users SET last_login_at = $2 WHERE id = $1 RETURNING *`,
    [user._id, loginAt.toISOString()]
  );

  const updatedUser = rowToUserDocument(updatedResult.rows[0]);
  const session = await createSessionForUser({
    user: updatedUser,
  });

  return {
    ...session,
    user: toEmailAuthUser(updatedUser),
  };
}

async function getSessionAndUserFromToken(sessionToken: string | null) {
  if (!sessionToken) {
    return null;
  }

  await ensureSchema();
  const pool = getPool();
  const sessionHash = createScopedHash("session", sessionToken);
  const sessionResult = await pool.query<EmailAuthSessionRow>(
    `SELECT * FROM auth_email_sessions
     WHERE token_hash = $1 AND expires_at > now()`,
    [toHex(sessionHash)]
  );
  const session = sessionResult.rows[0] ? rowToSessionDocument(sessionResult.rows[0]) : null;

  if (!session) {
    return null;
  }

  const userResult = await pool.query<EmailAuthUserRow>(
    `SELECT * FROM auth_email_users WHERE id = $1`,
    [session.userId]
  );
  const userRow = userResult.rows[0];

  if (!userRow) {
    await pool.query(`DELETE FROM auth_email_sessions WHERE id = $1`, [session.id]);
    return null;
  }

  return {
    user: rowToUserDocument(userRow),
    session,
  };
}

export async function getEmailAuthUserFromToken(sessionToken: string | null) {
  const resolved = await getSessionAndUserFromToken(sessionToken);

  if (!resolved) {
    return null;
  }

  void getPool()
    .query(`UPDATE auth_email_sessions SET last_seen_at = now() WHERE id = $1`, [
      resolved.session.id,
    ])
    .catch(() => undefined);

  return toEmailAuthUser(resolved.user);
}

export async function updateEmailAuthProfile({
  sessionToken,
  name,
  image,
}: {
  sessionToken: string | null;
  name?: string;
  image?: string | null;
}) {
  if (!sessionToken) {
    throw new EmailAuthApiError("You must be logged in to update profile.", 401);
  }

  const resolved = await getSessionAndUserFromToken(sessionToken);

  if (!resolved) {
    throw new EmailAuthApiError("Your session is not valid. Please log in again.", 401);
  }

  const updates: { name?: string; image?: string | null } = {};

  if (typeof name !== "undefined") {
    updates.name = normalizeDisplayName(name);
  }

  if (typeof image !== "undefined") {
    updates.image = normalizeProfileImageDataUrl(image);
  }

  if (!Object.keys(updates).length) {
    throw new EmailAuthApiError("No profile changes were provided.", 400);
  }

  await ensureSchema();
  const pool = getPool();
  const updatedResult = await pool.query<EmailAuthUserRow>(
    `UPDATE auth_email_users
     SET name = COALESCE($2, name), image = COALESCE($3, image)
     WHERE id = $1
     RETURNING *`,
    [resolved.user._id, updates.name ?? null, updates.image ?? null]
  );

  return toEmailAuthUser(rowToUserDocument(updatedResult.rows[0]));
}

export async function revokeEmailAuthSession(sessionToken: string | null) {
  if (!sessionToken) {
    return;
  }

  await ensureSchema();
  const pool = getPool();
  await pool.query(`DELETE FROM auth_email_sessions WHERE token_hash = $1`, [
    toHex(createScopedHash("session", sessionToken)),
  ]);
}

export function getEmailAuthCookieOptions(expiresAt: Date) {
  return {
    name: EMAIL_AUTH_SESSION_COOKIE_NAME,
    value: "",
    options: {
      httpOnly: true,
      sameSite: "lax" as const,
      secure: process.env.NODE_ENV === "production",
      path: "/",
      expires: expiresAt,
    },
  };
}
