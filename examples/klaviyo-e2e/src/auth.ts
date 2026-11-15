/**
 * Local Better Auth (email/password + bearer sessions) with three seeded users.
 * https://www.better-auth.com/docs/authentication/email-password
 * https://www.better-auth.com/docs/plugins/bearer
 * https://www.better-auth.com/docs/adapters/sqlite (node:sqlite)
 */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { required } from "./env.ts";
import { ROLES, USERS, roleForEmail, type RoleName } from "./roles.ts";

export interface SeededUser {
  role: RoleName;
  email: string;
  id?: string;
}

export function createAuth(opts: { baseURL: string; dbPath: string; secret: string }) {
  mkdirSync(dirname(opts.dbPath), { recursive: true });
  const db = new DatabaseSync(opts.dbPath);
  const auth = betterAuth({
    secret: opts.secret,
    baseURL: opts.baseURL,
    basePath: "/api/auth",
    database: db,
    emailAndPassword: { enabled: true, minPasswordLength: 12 },
    trustedOrigins: [opts.baseURL, opts.baseURL.replace("127.0.0.1", "localhost")],
    plugins: [bearer()],
  });
  return { auth, db };
}

export async function migrateAuth(auth: ReturnType<typeof betterAuth>): Promise<void> {
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();
}

export async function seedUsers(auth: ReturnType<typeof betterAuth>): Promise<SeededUser[]> {
  const out: SeededUser[] = [];
  for (const role of ROLES) {
    const email = process.env[USERS[role].emailEnv] ?? USERS[role].defaultEmail;
    const password = required(USERS[role].passwordEnv);
    const name = USERS[role].name;
    try {
      const created = await auth.api.signUpEmail({ body: { email, password, name } });
      const id = (created as { user?: { id?: string } } | null)?.user?.id;
      out.push({ role, email, id });
    } catch {
      const signed = await auth.api.signInEmail({ body: { email, password } });
      const id = (signed as { user?: { id?: string } } | null)?.user?.id;
      const emailOk = (signed as { user?: { email?: string } } | null)?.user?.email;
      if (!id && !emailOk) {
        throw new Error(`seed failed for ${role}: could not create or sign in (password in .env may not match an existing user; delete data/better-auth.sqlite and re-run)`);
      }
      out.push({ role, email, id });
    }
  }
  return out;
}

export async function sessionFromBearer(auth: ReturnType<typeof betterAuth>, token: string) {
  const session = await auth.api.getSession({
    headers: new Headers({ authorization: `Bearer ${token}` }),
  });
  if (!session?.user?.email) return null;
  const role = roleForEmail(session.user.email);
  if (!role) return null;
  return { session, role, email: session.user.email, userId: String(session.user.id) };
}
