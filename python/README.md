# mcp-rbac (Python)

Authorization for Python MCP servers built on the official SDK (`mcp>=2.3`, `MCPServer`). Same policy model,
JSON policy format, audit-chain format, Redis/Postgres schemas and AuthZEN mapping as the TypeScript `mcp-rbac`.

```python
from typing import Literal
from mcp.server.mcpserver import MCPServer
from mcp_rbac import Role, Limit
from mcp_rbac.mcpserver import RBAC, JwtVerifier

R = Literal["owner", "manager", "analyst"]
rbac = RBAC[R](roles={"owner": Role.everything(), "manager": Role.of("get_*"), "analyst": Role.of("get_*")})
server = MCPServer("shop", token_verifier=JwtVerifier(KEY, issuer=ISS, audience=AUD), auth=...)

@server.tool()
@rbac.tool(allow=["manager"], scopes=["campaigns:write"], approve=True, limits=[Limit("*", max=20, window_s=86400)])
async def send_campaign(campaign_id: str) -> str: ...

rbac.install(server)   # every tool is deny-by-default; tools/list is filtered per caller
```

See `../docs/python.md` for the full guide.
