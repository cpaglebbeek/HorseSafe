from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

AuditEvent = Literal[
    "register",
    "login_success",
    "login_fail",
    "login_throttled",
    "mfa_setup_totp",
    "mfa_pass_totp",
    "mfa_pass_magic_link",
    "mfa_fail",
    "logout",
    "session_expired",
    "vault_create",
    "vault_read",
    "vault_update",
    "vault_delete",
    "vault_etag_conflict",
    "export_kdbx",
    "export_csv",
    "export_json",
    "export_xlsx",
    "import_kdbx",
    "import_bitwarden",
    "import_csv",
    "import_xlsx",
    "admin_user_create",
    "admin_user_delete",
    "admin_stats_view",
    "admin_audit_view",
    "admin_user_disable_mfa",
    "admin_user_send_magic_link",
    "backup_codes_generate",
    "backup_codes_consume",
    "account_password_changed",
    "admin_audit_csv_export",
    "input_rejected",
]


class AuditEntry(BaseModel):
    user_id: str | None
    ts: int
    ip: str | None
    user_agent: str | None
    event: AuditEvent
    detail: str | None = None
    reason: str | None = None
