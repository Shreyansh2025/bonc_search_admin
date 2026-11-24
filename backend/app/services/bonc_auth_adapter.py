"""Adapter connecting the reusable ``bonc-auth`` package to ``BoncTokenVerifier``.

Architectural status:
- **Prepared, unactivated candidate adapter.** ``admin_auth.build_default_auth_provider()``
  intentionally keeps BONC authentication unconfigured and fail-closed (HTTP 503)
  until BONC's .NET team confirms the final verification mechanism and trusted
  claims contract.
- **Preferred production path (pending .NET confirmation):** Local cryptographic
  JWT verification (JWKS, public key, or verified shared secret) behind the same
  ``BoncTokenVerifier`` interface.
- **This adapter** wraps ``bonc_auth.BoncAuth`` (HTTP verification endpoint client)
  via package imports without duplicating package code, while strictly preserving
  Search_Admin's centralized ``BoncJwtAuthProvider``, ``validate_verified_bonc_identity``,
  ``BoncRoleAuthorizationPolicy``, and route-level permission boundaries.

Fail-closed guarantees:
- Never invents or defaults missing ``issuer``, ``audience``, ``expires_at_utc``,
  ``algorithm``, or ``roles`` values.
- Raises ``BoncAuthUnavailableError`` (HTTP 503) — never HTTP 401 — when an HTTP
  200 response from the .NET verification endpoint omits required trusted claims
  or contains malformed/conflicting field types.
- Never uses ``bonc_auth.fastapi.FastAPIAdminGuard`` to bypass ``BoncJwtAuthProvider``.
"""
from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from bonc_auth import (
    AuthServiceUnavailable,
    BoncAuth,
    BoncAuthError,
    Forbidden,
    InvalidToken,
)

from app.services.bonc_auth import (
    BoncAuthorizationDeniedError,
    BoncAuthNotConfiguredError,
    BoncAuthUnavailableError,
    BoncTokenInvalidError,
    BoncTokenVerifier,
    VerifiedBoncIdentity,
)

_MAX_USER_ID_LENGTH = 256
_MAX_SHORT_CLAIM_LENGTH = 128
_MAX_LONG_CLAIM_LENGTH = 256


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _extract_aliased_value(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[bool, Any]:
    """Return ``(present, value)`` for alias keys, failing closed on conflicting values."""
    present_entries = [(key, payload[key]) for key in keys if key in payload]
    if not present_entries:
        return False, None
    non_null_values = [value for _, value in present_entries if value is not None]
    if not non_null_values:
        return True, None
    first = non_null_values[0]
    for other in non_null_values[1:]:
        if other != first:
            raise BoncAuthUnavailableError(
                f"Conflicting {field_name} values in BONC verification response"
            )
    return True, first


def _parse_required_non_empty_str(
    value: Any,
    *,
    field_name: str,
    max_length: int = _MAX_LONG_CLAIM_LENGTH,
) -> str:
    if not isinstance(value, str):
        raise BoncAuthUnavailableError(
            f"BONC verification response has invalid {field_name} type"
        )
    if _has_control_chars(value):
        raise BoncAuthUnavailableError(
            f"BONC verification response has malformed {field_name}"
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length:
        raise BoncAuthUnavailableError(
            f"BONC verification response has empty or oversized {field_name}"
        )
    return cleaned


def _parse_optional_str(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    field_name: str,
    max_length: int = _MAX_LONG_CLAIM_LENGTH,
) -> str | None:
    present, value = _extract_aliased_value(payload, keys, field_name=field_name)
    if not present or value is None:
        return None
    return _parse_required_non_empty_str(
        value,
        field_name=field_name,
        max_length=max_length,
    )


def _parse_optional_audience(payload: Mapping[str, Any]) -> str | tuple[str, ...] | None:
    present, value = _extract_aliased_value(
        payload,
        ("aud", "audience"),
        field_name="audience",
    )
    if not present or value is None:
        return None
    if isinstance(value, str):
        return _parse_required_non_empty_str(value, field_name="audience")
    if isinstance(value, (list, tuple)):
        if not value:
            raise BoncAuthUnavailableError(
                "BONC verification response has empty audience list"
            )
        parsed = tuple(
            _parse_required_non_empty_str(item, field_name="audience")
            for item in value
        )
        return parsed
    raise BoncAuthUnavailableError(
        "BONC verification response has invalid audience type"
    )


def _parse_utc_timestamp(value: Any, *, field_name: str) -> datetime:
    """Parse a Unix epoch timestamp or timezone-aware ISO-8601 UTC string."""
    if isinstance(value, bool):
        raise BoncAuthUnavailableError(
            f"BONC verification response has invalid {field_name} timestamp type"
        )
    if isinstance(value, (int, float)):
        numeric = float(value)
        if not math.isfinite(numeric) or numeric <= 0:
            raise BoncAuthUnavailableError(
                f"BONC verification response has invalid {field_name} numeric timestamp"
            )
        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError) as exc:
            raise BoncAuthUnavailableError(
                f"BONC verification response has out-of-range {field_name} timestamp"
            ) from exc

    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or _has_control_chars(cleaned):
            raise BoncAuthUnavailableError(
                f"BONC verification response has malformed {field_name} timestamp"
            )
        normalized = cleaned[:-1] + "+00:00" if cleaned.endswith(("Z", "z")) else cleaned
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise BoncAuthUnavailableError(
                f"BONC verification response has unparseable {field_name} timestamp"
            ) from exc
        if parsed.tzinfo is None:
            raise BoncAuthUnavailableError(
                f"BONC verification response {field_name} timestamp must include timezone"
            )
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)

    raise BoncAuthUnavailableError(
        f"BONC verification response has invalid {field_name} timestamp type"
    )


def _parse_optional_timestamp(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    field_name: str,
) -> datetime | None:
    present_entries = [(key, payload[key]) for key in keys if key in payload]
    if not present_entries:
        return None
    parsed_values: list[datetime] = []
    for _, raw in present_entries:
        if raw is None:
            continue
        parsed_values.append(_parse_utc_timestamp(raw, field_name=field_name))
    if not parsed_values:
        return None
    first = parsed_values[0]
    for other in parsed_values[1:]:
        if other != first:
            raise BoncAuthUnavailableError(
                f"Conflicting {field_name} values in BONC verification response"
            )
    return first


def _parse_string_collection(
    payload: Mapping[str, Any],
    *,
    singular_key: str | None,
    plural_key: str,
    field_name: str,
) -> tuple[str, ...]:
    collected: list[str] = []
    seen: set[str] = set()

    if plural_key in payload and payload[plural_key] is not None:
        raw_plural = payload[plural_key]
        if not isinstance(raw_plural, (list, tuple)):
            raise BoncAuthUnavailableError(
                f"BONC verification response has invalid {plural_key} type"
            )
        for item in raw_plural:
            cleaned = _parse_required_non_empty_str(
                item,
                field_name=field_name,
                max_length=_MAX_SHORT_CLAIM_LENGTH,
            )
            if cleaned not in seen:
                seen.add(cleaned)
                collected.append(cleaned)

    if singular_key and singular_key in payload and payload[singular_key] is not None:
        raw_singular = payload[singular_key]
        cleaned = _parse_required_non_empty_str(
            raw_singular,
            field_name=field_name,
            max_length=_MAX_SHORT_CLAIM_LENGTH,
        )
        if cleaned not in seen:
            seen.add(cleaned)
            collected.append(cleaned)

    return tuple(collected)


def parse_bonc_auth_payload(payload: Mapping[str, Any]) -> VerifiedBoncIdentity:
    """Strictly convert a verified ``bonc-auth`` JSON dict into ``VerifiedBoncIdentity``.

    Fails closed with ``BoncAuthUnavailableError`` (HTTP 503) if ``payload`` is
    malformed, has invalid or conflicting field types, or omits required trusted
    claims (``issuer``, ``audience``, ``expires_at_utc``). Never fabricates claims.
    """
    if not isinstance(payload, Mapping):
        raise BoncAuthUnavailableError("BONC verification response must be a JSON object")

    if "adminId" not in payload or payload["adminId"] is None:
        raise BoncAuthUnavailableError("BONC verification response is missing adminId")
    user_id = _parse_required_non_empty_str(
        payload["adminId"],
        field_name="adminId",
        max_length=_MAX_USER_ID_LENGTH,
    )

    username = _parse_optional_str(
        payload,
        ("username", "userName"),
        field_name="username",
        max_length=_MAX_LONG_CLAIM_LENGTH,
    )
    session_id = _parse_optional_str(
        payload,
        ("sessionId",),
        field_name="sessionId",
        max_length=_MAX_SHORT_CLAIM_LENGTH,
    )
    issuer = _parse_optional_str(
        payload,
        ("iss", "issuer"),
        field_name="issuer",
        max_length=_MAX_LONG_CLAIM_LENGTH,
    )
    audience = _parse_optional_audience(payload)
    expires_at_utc = _parse_optional_timestamp(
        payload,
        ("exp", "expiresAtUtc", "expiresAt"),
        field_name="expires_at_utc",
    )
    not_before_utc = _parse_optional_timestamp(
        payload,
        ("nbf", "notBeforeUtc"),
        field_name="not_before_utc",
    )
    issued_at_utc = _parse_optional_timestamp(
        payload,
        ("iat", "issuedAtUtc"),
        field_name="issued_at_utc",
    )
    algorithm = _parse_optional_str(
        payload,
        ("alg", "algorithm"),
        field_name="algorithm",
        max_length=64,
    )
    key_id = _parse_optional_str(
        payload,
        ("kid", "keyId"),
        field_name="key_id",
        max_length=_MAX_SHORT_CLAIM_LENGTH,
    )
    token_type = _parse_optional_str(
        payload,
        ("typ", "tokenType"),
        field_name="token_type",
        max_length=64,
    )
    token_id = _parse_optional_str(
        payload,
        ("jti", "tokenId"),
        field_name="token_id",
        max_length=_MAX_SHORT_CLAIM_LENGTH,
    )
    roles = _parse_string_collection(
        payload,
        singular_key="role",
        plural_key="roles",
        field_name="roles",
    )
    permissions = _parse_string_collection(
        payload,
        singular_key=None,
        plural_key="permissions",
        field_name="permissions",
    )

    missing_claims: list[str] = []
    if issuer is None:
        missing_claims.append("issuer")
    if audience is None:
        missing_claims.append("audience")
    if expires_at_utc is None:
        missing_claims.append("expires_at_utc")
    if missing_claims:
        raise BoncAuthUnavailableError(
            "BONC verification response is missing required trusted claims: "
            + ", ".join(missing_claims)
        )

    return VerifiedBoncIdentity(
        user_id=user_id,
        username=username,
        expires_at_utc=expires_at_utc,
        issuer=issuer,
        audience=audience,
        not_before_utc=not_before_utc,
        issued_at_utc=issued_at_utc,
        algorithm=algorithm,
        key_id=key_id,
        token_type=token_type,
        token_id=token_id,
        roles=roles,
        permissions=permissions,
        session_id=session_id,
    )


class BoncAuthPackageVerifierAdapter(BoncTokenVerifier):
    """``BoncTokenVerifier`` adapter delegating verification to ``bonc_auth.BoncAuth``.

    Does not duplicate HTTP client logic from ``bonc-auth`` and does not bypass
    Search_Admin's ``BoncJwtAuthProvider``, ``validate_verified_bonc_identity``,
    or ``BoncRoleAuthorizationPolicy``.
    """

    def __init__(self, client: BoncAuth | None = None) -> None:
        self._client = client

    @property
    def client(self) -> BoncAuth | None:
        return self._client

    @classmethod
    def from_settings(
        cls,
        *,
        verify_url: str,
        method: str = "GET",
        timeout: float = 5.0,
        service_headers: Mapping[str, str] | None = None,
    ) -> BoncAuthPackageVerifierAdapter:
        """Instantiate an adapter using ``bonc_auth.BoncAuth``'s built-in validation."""
        client = BoncAuth(
            verify_url,
            method=method,
            timeout=timeout,
            service_headers=service_headers,
        )
        return cls(client=client)

    def is_configured(self) -> bool:
        return self._client is not None

    def verify_access_token(self, raw_token: str) -> VerifiedBoncIdentity:
        if self._client is None:
            raise BoncAuthNotConfiguredError("BONC authentication verifier is not configured")

        try:
            payload = self._client.verify(raw_token)
        except InvalidToken as exc:
            raise BoncTokenInvalidError(
                "BONC token is invalid, expired, or its session is inactive"
            ) from exc
        except Forbidden as exc:
            raise BoncAuthorizationDeniedError("Administrator access required") from exc
        except AuthServiceUnavailable as exc:
            raise BoncAuthUnavailableError(
                "BONC verification service is unavailable or returned an invalid response"
            ) from exc
        except BoncAuthError as exc:
            raise BoncAuthUnavailableError(
                "BONC verification service returned an unexpected error"
            ) from exc

        return parse_bonc_auth_payload(payload)
