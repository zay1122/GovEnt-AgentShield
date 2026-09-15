#!/usr/bin/env python3
"""HTTP API for the controlled runtime and approval console."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from approval_store import ApprovalError
from auth import AuthError, TokenAuthenticator
from policy_engine import Principal
from runtime_controller import ExecutionError, SecureAgentRuntime


def create_app(project_root: Path | None = None, *, runtime_instance: SecureAgentRuntime | None = None,
               authenticator_instance: TokenAuthenticator | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("AGENTSHIELD_MAX_REQUEST_BYTES", "262144"))
    runtime = runtime_instance or SecureAgentRuntime(project_root)
    authenticator = authenticator_instance or TokenAuthenticator(project_root)

    def actor() -> Principal:
        return authenticator.authenticate(request.headers.get("Authorization"))

    @app.errorhandler(AuthError)
    def handle_auth_error(exc: AuthError) -> tuple[Any, int]:
        return jsonify({"error": str(exc)}), exc.status_code

    @app.errorhandler(ValueError)
    @app.errorhandler(TypeError)
    @app.errorhandler(ApprovalError)
    @app.errorhandler(ExecutionError)
    def handle_known_error(exc: Exception) -> tuple[Any, int]:
        return jsonify({"error": str(exc)}), 400

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(_exc: RequestEntityTooLarge) -> tuple[Any, int]:
        return jsonify({"error": "request body exceeds configured size limit"}), 413

    def json_object() -> dict[str, Any]:
        payload = request.get_json(silent=False)
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object")
        return payload

    @app.get("/health")
    def health() -> Any:
        return jsonify({"service": "govent-agentshield", "status": "ok",
                        "auth_mode": authenticator.mode,
                        "audit": runtime.audit.verify()})

    @app.post("/v1/runtime/submit")
    def submit() -> Any:
        payload = json_object()
        if "execute" in payload and not isinstance(payload["execute"], bool):
            raise ValueError("execute must be a JSON boolean")
        payload["principal"] = actor()
        return jsonify(runtime.submit(**payload))

    @app.get("/v1/approvals")
    def list_approvals() -> Any:
        current = actor()
        if current.role not in {"manager", "security_admin"}:
            return jsonify({"error": "approval list requires manager or security_admin"}), 403
        return jsonify(runtime.approvals.list(request.args.get("status")))

    @app.post("/v1/approvals/<approval_id>/decision")
    def decide(approval_id: str) -> Any:
        payload = json_object()
        if "approve" not in payload or not isinstance(payload["approve"], bool):
            raise ValueError("approve boolean is required")
        return jsonify(runtime.decide_approval(
            approval_id,
            actor=actor(),
            approve=payload["approve"],
            note=str(payload.get("note", "")),
        ))

    @app.get("/v1/audit/verify")
    def verify_audit() -> Any:
        current = actor()
        if current.role not in {"manager", "security_admin"}:
            return jsonify({"error": "audit verification requires elevated role"}), 403
        return jsonify(runtime.audit.verify())

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("AGENTSHIELD_HOST", "127.0.0.1"),
        port=int(os.environ.get("AGENTSHIELD_PORT", "8080")),
        debug=False,
    )
