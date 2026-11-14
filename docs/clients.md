# Client configuration

The proxy is itself a stdio MCP server. Wherever a client launches `<server command>`, launch `mcp-rbac proxy [options] -- <server command>` instead. Nothing changes in the server.

Use **absolute paths** in `--paths`, because the proxy refuses relative and `~` paths in arguments. The shell expands `~` in a terminal, but JSON configs don't.

## Claude Desktop (`claude_desktop_config.json`)

Claude Desktop did **not** advertise MCP elicitation in public client-support matrices as of Sept 2026. With `--approval auto` (the default), approvals go to the terminal queue: run `mcp-rbac pending --watch` in a terminal while you work. Alternatives: use `read-only` / `no-destructive`, which need no approvals, or `--approval deny`.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "mcp-rbac", "proxy", "--preset", "no-destructive", "--paths", "/Users/me/proj",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/proj"]
    },
    "git": {
      "command": "npx",
      "args": ["-y", "mcp-rbac", "proxy", "--preset", "read-only", "--paths", "/Users/me/proj",
               "--", "uvx", "mcp-server-git"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "mcp-rbac", "proxy", "--preset", "approve-destructive", "--repos", "my-org/my-app",
               "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..." }
    }
  }
}
```

`env` is passed through the proxy to the server unchanged.

## Cursor (`.cursor/mcp.json` or `~/.cursor/mcp.json`)

Cursor supports elicitation, so `approve-writes` shows each write in Cursor for you to approve or decline.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "mcp-rbac", "proxy", "--preset", "approve-writes", "--paths", "/Users/me/proj/src,/Users/me/proj/docs",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/proj"]
    }
  }
}
```

## VS Code (`.vscode/mcp.json`)

```json
{
  "servers": {
    "filesystem": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-rbac", "proxy", "--preset", "approve-writes", "--paths", "${workspaceFolder}",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "${workspaceFolder}"]
    }
  }
}
```

## Claude Code

```bash
claude mcp add files -- npx -y mcp-rbac proxy --preset approve-writes --paths "$PWD" -- npx -y @modelcontextprotocol/server-filesystem "$PWD"
```

## What was verified here

- **Tested:** the proxy against the real servers via the official TypeScript SDK client over stdio, both with an elicitation capability (Cursor/VS Code/Claude Code style) and without one (Claude Desktop style). See `test/real-servers.e2e.test.ts`.
- **Not tested:** the GUI apps themselves; they weren't available on this machine.
- **Client name.** The audit log records the client's `clientInfo.name` as the agent.

## Remote (hosted) servers

Put `--url` in place of `-- <command>`. The client still launches a local stdio process; the proxy holds the connection and the credentials.

```jsonc
// claude_desktop_config.json  /  .cursor/mcp.json
{ "mcpServers": {
  "deepwiki": { "command": "npx", "args": ["-y", "mcp-rbac", "proxy", "--url", "https://mcp.deepwiki.com/mcp", "--preset", "read-only"] },
  "linear":   { "command": "npx", "args": ["-y", "mcp-rbac", "proxy", "--url", "https://mcp.linear.app/mcp", "--preset", "approve-writes"] },
  "internal": { "command": "npx", "args": ["-y", "mcp-rbac", "proxy", "--url", "https://mcp.internal.example/mcp",
                                            "--header", "Authorization: Bearer $INTERNAL_MCP_TOKEN"],
                "env": { "INTERNAL_MCP_TOKEN": "..." } }
} }
```

- **OAuth servers.** Run `npx mcp-rbac login --url https://mcp.linear.app/mcp` once in a terminal. It opens the browser, waits on `http://127.0.0.1:33418/callback`, and stores tokens 0600 in `~/.mcp-rbac/oauth/`. After that the client starts the proxy without a prompt, and tokens refresh automatically. If you skip `login`, the proxy opens the browser on first start, but some clients give up on a server that takes longer than about 60 s to initialize.
- **Don't also configure the URL directly.** If the same server is in the client config without the proxy, or the agent has a shell or fetch tool that can reach it, the policy is bypassed.
- `--header` values expand `$VAR` from the process environment (the client's `env` block). Keep tokens there, not in `args`.
- `--no-oauth` makes a 401 fail with what the server asked for. `mcp-rbac auth-info --url <url>` prints the same, read-only.
- For servers you host yourself, the library's `serveGuardedHttp` (Streamable HTTP + OAuth bearer/JWT) is still the in-process option.
