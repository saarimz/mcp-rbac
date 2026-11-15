"""RS256 variant of the demo IdP (same claims as examples/servers/shared/auth.py mint) for gateways whose JWT validation
does not support HS256 (agentgateway: RSA/EC/OKP only). Keys are generated per run under results/keys (gitignored)."""
from __future__ import annotations

import base64
import json
import pathlib
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "mcp-guard-demo-idp"
KEYS = pathlib.Path(__file__).resolve().parent / "results" / "keys"


def _key(name: str) -> rsa.RSAPrivateKey:
    KEYS.mkdir(parents=True, exist_ok=True)
    p = KEYS / f"{name}.pem"
    if not p.exists():
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return serialization.load_pem_private_key(p.read_bytes(), password=None)  # type: ignore[return-value]


def jwks_file() -> str:
    pub = _key("idp").public_key().public_numbers()
    b = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()  # noqa: E731
    p = KEYS / "jwks.json"
    p.write_text(json.dumps({"keys": [{"kty": "RSA", "kid": "idp", "alg": "RS256", "use": "sig", "n": b(pub.n), "e": b(pub.e)}]}))
    return str(p)


def mint_rs256(claims: dict[str, Any], key: str = "idp") -> str:
    t = int(time.time())
    body = {"iss": ISSUER, "iat": t, "exp": t + 900, "jti": str(uuid.uuid4()), **claims}
    return jwt.encode(body, _key(key), algorithm="RS256", headers={"kid": "idp"})
