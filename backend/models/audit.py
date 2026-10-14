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
    "keypair_generated",
    "share_create",
    "share_accept",
    "share_decline",
    "input_rejected",
    # v0.2.0-Koblitz — hardware-sleutels (docs/HARDWARE_KEYS.md §12.10). Detail bevat nooit
    # sealed, ph, kh, PRF-uitvoer, challenges, client-data, signatures, TOTP-codes of SMTP-gegevens.
    "vault_key_add",
    "vault_key_add_rejected",
    "vault_key_delete",
    "vault_key_unlock",
    "vault_key_reseal",
    "vault_key_clone_suspect",
    "vault_rekey",
    "recovery_release_request",
    "recovery_release_cancel",
    "recovery_key_used",
    "recovery_block",
    "recovery_unblock",
    "recovery_unblock_rejected",
    "stepup",
    "stepup_fail",
    "notify_failed",
    # v0.3.4-Miller deel 2 — telefoon koppelen (docs/HARDWARE_KEYS.md §13.8). Detail bevat nooit
    # s, k_srv, MAC's, sealed of attestatieketens.
    "device_pairing_start",
    "device_pairing_claim",
    "device_pairing_confirm",
    "device_pairing_cancel",
    "device_pairing_rejected",
    "device_revoke",
]


class AuditEntry(BaseModel):
    user_id: str | None
    ts: int
    ip: str | None
    user_agent: str | None
    event: AuditEvent
    detail: str | None = None
    reason: str | None = None
