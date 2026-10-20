"""AWS identity verification via STS GetCallerIdentity (read-only)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from .config import DEFAULT_REGION, ScanConfig
from .errors import classify_exception, error_message


@dataclass
class IdentityResult:
    account_id: str | None
    caller_arn: str | None
    user_id: str | None
    profile: str | None
    region: str | None
    credential_source: str | None
    success: bool
    error: str | None = None
    error_type: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "caller_arn": self.caller_arn,
            "user_id": self.user_id,
            "profile": self.profile,
            "region": self.region,
            "credential_source": self.credential_source,
            "success": self.success,
            "error": self.error,
            "error_type": self.error_type,
        }


def create_session(config: ScanConfig, region: str | None = None) -> boto3.Session:
    """Create a Boto3 session from profile/env configuration (no inline secrets)."""
    kwargs: dict[str, Any] = {"region_name": region or config.regions[0] or DEFAULT_REGION}
    if config.profile:
        kwargs["profile_name"] = config.profile
    return boto3.Session(**kwargs)


def get_identity(config: ScanConfig, session: boto3.Session | None = None) -> IdentityResult:
    region = config.regions[0] if config.regions else DEFAULT_REGION
    try:
        session = session or create_session(config, region)
        sts = session.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        return IdentityResult(
            account_id=identity.get("Account"),
            caller_arn=identity.get("Arn"),
            user_id=identity.get("UserId"),
            profile=config.profile,
            region=region,
            credential_source=_credential_source(session),
            success=True,
        )
    except (ClientError, BotoCoreError, NoCredentialsError, ProfileNotFound) as exc:
        return IdentityResult(
            account_id=None,
            caller_arn=None,
            user_id=None,
            profile=config.profile,
            region=region,
            credential_source=None,
            success=False,
            error=error_message(exc),
            error_type=classify_exception(exc),
        )


def _credential_source(session: boto3.Session) -> str | None:
    """Describe where credentials came from without exposing any secret value."""
    try:
        creds = session.get_credentials()
        if creds is None:
            return None
        method = getattr(creds, "method", None)
        return str(method) if method else "unknown"
    except Exception:  # pragma: no cover - defensive
        return None


def format_identity(result: IdentityResult) -> str:
    lines = [
        f"Account ID    : {result.account_id or 'N/A'}",
        f"Caller ARN    : {result.caller_arn or 'N/A'}",
        f"User ID       : {result.user_id or 'N/A'}",
        f"Profile       : {result.profile or '(default chain)'}",
        f"Region        : {result.region or 'N/A'}",
        f"Creds source  : {result.credential_source or 'N/A'}",
    ]
    if not result.success:
        lines.append(f"ERROR ({result.error_type}): {result.error}")
    return "\n".join(lines)
