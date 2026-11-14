// Child process: hammer the shared counter, print how many consumes succeeded.
import { Redis } from "ioredis";
import pg from "pg";
import { RedisStore } from "../../src/store-redis.js";
import { PostgresStore } from "../../src/store-postgres.js";

const [kind, url, key, nStr, maxStr, now] = process.argv.slice(2);
const n = Number(nStr), max = Number(maxStr);
let store: RedisStore | PostgresStore;
let closer: () => Promise<unknown>;
if (kind === "redis") { const r = new Redis(url!); store = new RedisStore(r as any, { prefix: "t:" }); closer = () => r.quit(); }
else { const pool = new pg.Pool({ connectionString: url, max: 8 }); store = await PostgresStore.connect(pool, { table: "t7" }); closer = () => pool.end(); }
const res = await Promise.all(Array.from({ length: n }, () => store.consumeMany!([{ key: key!, amount: 1, max, windowMs: 3_600_000 }, { key: `${key}|b`, amount: 1, max: max * 10, windowMs: 3_600_000 }], Number(now))));
console.log(JSON.stringify({ ok: res.filter((r) => r.ok).length }));
await closer();
