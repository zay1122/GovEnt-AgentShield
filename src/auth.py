#!/usr/bin/env python3
"""Local bearer-token authentication adapter for the prototype API."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path

from policy_engine import Principal


class AuthError(RuntimeError):
    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


class TokenAuthenticator:
    """Authenticate Bearer tokens against SHA-256 digests.

    The bundled identities are explicitly local demonstration accounts. The
    file location is replaceable with AGENTSHIELD_AUTH_FILE so deployments can
    inject their own secret-backed identity map without editing source code.
    """

    def __init__(self, project_root: Path | None = None, auth_file: Path | None = None) -> None:
        root = (project_root or Path(__file__).resolve().parents[1]).resolve()
        configured = os.environ.get("AGENTSHIELD_AUTH_FILE")
        self.path = Path(configured).resolve() if configured else (auth_file or root / "config" / "identities.json")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthError(f"identity configuration unavailable: {exc}", 503) from exc
        identities = value.get("identities")
        if not isinstance(identities, list) or not identities:
            raise AuthError("identity configuration contains no identities", 503)
        self.mode = str(value.get("mode", "unknown"))
        allowed_roles = {"guest", "employee", "manager", "security_admin"}
        seen_users: set[str] = set()
        seen_digests: set[str] = set()
        validated: list[dict[str, str]] = []
        for index, identity in enumerate(identities):
            if not isinstance(identity, dict):
                raise AuthError(f"identity[{index}] is not an object", 503)
            user_id = str(identity.get("user_id", "")).strip()
            role = str(identity.get("role", "")).strip()
            digest = str(identity.get("token_sha256", "")).lower()
            if not user_id or role not in allowed_roles or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise AuthError(f"identity[{index}] is invalid", 503)
            if user_id in seen_users or digest in seen_digests:
                raise AuthError("identity configuration contains duplicate users or tokens", 503)
            seen_users.add(user_id)
            seen_digests.add(digest)
            validated.append({
                "user_id": user_id,
                "role": role,
                "department": str(identity.get("department", "unknown")),
                "token_sha256": digest,
            })
        self._identities = validated

    def authenticate(self, authorization: str | None) -> Principal:
        scheme, _, token = str(authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthError("Authorization: Bearer <token> is required")
        digest = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        for identity in self._identities:
            expected = str(identity.get("token_sha256", ""))
            if len(expected) == 64 and hmac.compare_digest(digest, expected):
                return Principal(
                    user_id=str(identity["user_id"]),
                    role=str(identity["role"]),
                    department=str(identity.get("department", "unknown")),
                )
        raise AuthError("invalid bearer token")
