from typing import Literal

from mcp_rbac import Role
from mcp_rbac.mcpserver import RBAC

R = Literal["owner", "manager"]
rbac = RBAC[R]({"owner": Role.everything(), "manager": Role()})


@rbac.tool(allow=["manager"], redact_unless=["owner"])
def send_campaign(cid: str) -> str:
    return cid
