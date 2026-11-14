// Test fixture: the TS Klaviyo-style example on a random port, with one synthetic user per role.
import { DATA, serve } from "../../examples/klaviyo-style/server.js";
(DATA.roles as string[]).forEach((r, i) => { DATA.users[`tok-role-${i}`] = { id: `role${i}`, orgRoles: [{ role: r, access: "all" }] }; });
const state = { sent: [] as string[] };
const srv = await serve(0, state);
process.stdout.write(JSON.stringify({ url: srv.url }) + "\n");
let buf = "";
process.stdin.on("data", (d) => {
  buf += String(d);
  let i: number;
  while ((i = buf.indexOf("\n")) >= 0) {
    const cmd = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (cmd === "reset") state.sent.length = 0;
    process.stdout.write(JSON.stringify({ sent: state.sent }) + "\n");
  }
});
process.stdin.on("end", () => process.exit(0));
