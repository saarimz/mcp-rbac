import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function unquote(v: string): string {
  if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  return v;
}

/** Load a dotenv file into process.env without overwriting existing values. Never logs values. */
export function loadDotEnv(path = join(ROOT, ".env")): void {
  if (!existsSync(path)) return;
  for (const raw of readFileSync(path, "utf8").split(/\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (process.env[key] !== undefined) continue;
    process.env[key] = unquote(line.slice(eq + 1).trim());
  }
}

export function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing ${name} (run: npx tsx src/setup-env.ts)`);
  return v;
}

export function dataPath(envName: string, fallback: string): string {
  const v = process.env[envName] ?? fallback;
  return isAbsolute(v) ? v : join(ROOT, v);
}

export function port(envName: string, fallback: number): number {
  const raw = process.env[envName];
  if (!raw) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`invalid ${envName}`);
  return n;
}

/** Live Klaviyo private API key, if the operator has supplied one. Never log the value. */
export function klaviyoPrivateKey(): string | undefined {
  const v = process.env.KLAVIYO_PRIVATE_API_KEY || process.env.PRIVATE_API_KEY;
  return v && v.trim() ? v.trim() : undefined;
}

export function isSecretEnvName(name: string): boolean {
  return /PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE/i.test(name);
}
