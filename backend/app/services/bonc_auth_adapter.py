"""BONC .NET ``getUserDetail`` token verifier and SHA-256 success-only TTL cache.

This is the sole authentication verifier for Search Admin:
- Decodes the incoming JWT payload ONLY as an untrusted identifier to obtain
  ``UserRowId`` (never verifies signatures locally and never requires an HS256
  secret).
- Sends ``GET <BONC_AUTH_VERIFY_URL>?userRowId=<UserRowId>`` with the original,
  unchanged ``Authorization: Bearer <AuthToken>`` header and
  ``follow_redirects=False``.
- Relies on BONC .NET to authoritatively validate the token signature, expiry,
  and session/logout revocation state.
- Grants access ONLY when .NET returns HTTP 200, ``Success`` is not false, the
  returned ``UserRowId`` matches the token's ``UserRowId``, ``IsActive`` is not
  false, and the user holds at least one role in ``BONC_AUTH_ADMIN_ROLES``.
- Caches ONLY successful verifications keyed by ``SHA-256(token)`` (never raw
  tokens). Rejections (401/403) and service failures (503) are never cached.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Iterable, Mapping
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from app.services.bonc_auth import (
    BoncAuthorizationDeniedError,
    BoncAuthNotConfiguredError,
    BoncAuthUnavailableError,
    BoncClaimsValidationConfig,
    BoncJwtAuthProvider,
    BoncRoleAuthorizationPolicy,
    BoncTokenInvalidError,
    BoncTokenVerifier,
    VerifiedBoncIdentity,
)

_MAX_USER_ID_LENGTH = 256
_MAX_USER_DETAIL_ROW_ID_LENGTH = 128
_MAX_JWT_LENGTH = 8192
_MAX_LONG_CLAIM_LENGTH = 256
_ROLE_SPLIT_RE = re.compile(r"[,;|]")
_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _validate_verify_url(
    verify_url: str,
    *,
    timeout: float,
    service_headers: Mapping[str, str] | None = None,
) -> None:
    """Enforce HTTPS for remote endpoints (localhost allowed for local dev/tests)."""
    parsed = urlparse(verify_url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError("BONC_AUTH_VERIFY_URL must be an absolute HTTP(S) URL.")
    if parsed.scheme != "https" and parsed.hostname not in _LOCALHOST_HOSTS:
        raise ValueError("Use HTTPS for the BONC verification endpoint.")
    if not math.isfinite(float(timeout)) or float(timeout) <= 0:
        raise ValueError("timeout must be greater than zero.")
    if any(key.lower() == "authorization" for key in (service_headers or {})):
        raise ValueError("Do not set Authorization in service_headers.")


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


def extract_unverified_jwt_claims(token: str) -> dict[str, Any]:
    """Decode the JWT payload WITHOUT verifying its signature.

    Treated strictly as untrusted input used ONLY to obtain ``UserRowId`` so
    BONC's ``getUserDetail`` endpoint can be queried with the original,
    unchanged Bearer token and the response cross-checked against it.
    """
    if not isinstance(token, str) or len(token) > _MAX_JWT_LENGTH:
        return {}
    parts = token.split(".")
    if len(parts) != 3 or any(not seg for seg in parts):
        return {}
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(padded)
        claims = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def extract_user_detail_roles(detail: Mapping[str, Any]) -> list[str]:
    """Extract every role named in a .NET ``getUserDetail`` record.

    Inspects ``UserRoles``, ``RoleNames``, and ``RoleName`` (handling both list
    values and strings delimited by ``,``, ``;``, or ``|``).
    """
    out: list[str] = []
    for key in ("UserRoles", "RoleNames", "RoleName"):
        value = detail.get(key)
        items = value if isinstance(value, (list, tuple)) else [value]
        for item in items:
            if isinstance(item, str):
                for part in _ROLE_SPLIT_RE.split(item):
                    cleaned = part.strip()
                    if cleaned:
                        out.append(cleaned)
    return out


def _extract_untrusted_user_row_id(token: str) -> str:
    raw_uid = extract_unverified_jwt_claims(token).get("UserRowId")
    if isinstance(raw_uid, bool) or not isinstance(raw_uid, (str, int)):
        return ""
    cleaned = str(raw_uid).strip()
    if not cleaned or len(cleaned) > _MAX_USER_DETAIL_ROW_ID_LENGTH or _has_control_chars(cleaned):
        return ""
    return cleaned


def _extract_detail_user_row_id(detail: Mapping[str, Any]) -> str:
    present, value = _extract_aliased_value(
        detail,
        ("UserRowId", "userRowId"),
        field_name="UserRowId",
    )
    if not present or value is None or isinstance(value, bool):
        return ""
    if not isinstance(value, (str, int)):
        return ""
    cleaned = str(value).strip()
    if not cleaned or len(cleaned) > _MAX_USER_ID_LENGTH or _has_control_chars(cleaned):
        return ""
    return cleaned


def _is_user_detail_inactive(detail: Mapping[str, Any]) -> bool:
    for key in ("IsActive", "isActive"):
        if key not in detail:
            continue
        raw = detail.get(key)
        if raw is False:
            return True
        if isinstance(raw, int) and not isinstance(raw, bool) and raw == 0:
            return True
        if isinstance(raw, str) and raw.strip().lower() in {"false", "0"}:
            return True
    return False


def _extract_optional_display_username(detail: Mapping[str, Any]) -> str | None:
    for key in ("UserName", "Username", "username", "Email", "email", "FullName", "fullName"):
        raw = detail.get(key)
        if isinstance(raw, str) and not _has_control_chars(raw):
            cleaned = raw.strip()
            if cleaned:
                return cleaned[:_MAX_LONG_CLAIM_LENGTH]
    first = detail.get("FirstName") or detail.get("firstName")
    last = detail.get("LastName") or detail.get("lastName")
    parts = [
        p.strip()
        for p in (first, last)
        if isinstance(p, str) and not _has_control_chars(p) and p.strip()
    ]
    if parts:
        return " ".join(parts)[:_MAX_LONG_CLAIM_LENGTH]
    return None


class UserDetailAuth:
    """Verify a BONC Bearer token via .NET's ``GET /api/userService/getUserDetail``."""

    def __init__(
        self,
        verify_url: str,
        *,
        admin_roles: Iterable[str],
        timeout: float = 5.0,
        service_headers: Mapping[str, str] | None = None,
    ) -> None:
        _validate_verify_url(verify_url, timeout=timeout, service_headers=service_headers)
        role_map = {
            r.strip().lower(): r.strip()
            for r in admin_roles
            if isinstance(r, str) and r.strip()
        }
        if not role_map:
            raise ValueError(
                "BONC_AUTH_ADMIN_ROLES must include at least one role "
                "(e.g. Admin,SuperAdmin): with none, nobody could ever get in"
            )
        self.verify_url = verify_url
        self.timeout = float(timeout)
        self.admin_roles = role_map
        self.service_headers = dict(service_headers or {})

    def verify(self, token: str) -> VerifiedBoncIdentity:
        if not isinstance(token, str) or not token.strip():
            raise BoncTokenInvalidError("Bearer token is empty.")

        user_id = _extract_untrusted_user_row_id(token)
        if not user_id:
            raise BoncTokenInvalidError("Not a BONC sign-in token (no UserRowId claim).")

        headers = {
            **self.service_headers,
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        try:
            resp = httpx.get(
                self.verify_url,
                params={"userRowId": user_id},
                headers=headers,
                timeout=self.timeout,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise BoncAuthUnavailableError("Could not reach BONC authentication service.") from exc

        if resp.status_code == 401:
            raise BoncTokenInvalidError(
                "Token is invalid, expired, or the session is no longer active."
            )
        if resp.status_code == 403:
            raise BoncAuthorizationDeniedError("Administrator access required.")
        if resp.status_code != 200:
            raise BoncAuthUnavailableError(
                f"BONC getUserDetail returned HTTP {resp.status_code}."
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise BoncAuthUnavailableError("BONC returned an invalid JSON response.") from exc
        if not isinstance(body, dict):
            raise BoncAuthUnavailableError("BONC getUserDetail did not return a JSON object.")

        if body.get("Success") is False or body.get("success") is False:
            msg = str(body.get("Message") or body.get("message") or "")[:200]
            raise BoncAuthUnavailableError(f"BONC getUserDetail said Success=false: {msg}")

        if "Data" in body:
            raw_data = body.get("Data")
            if isinstance(raw_data, dict):
                detail: Mapping[str, Any] = raw_data
            elif raw_data is None:
                detail = body
            else:
                raise BoncAuthUnavailableError(
                    "BONC getUserDetail Data field is not a JSON object."
                )
        elif "data" in body and isinstance(body.get("data"), dict):
            detail = body["data"]
        else:
            detail = body

        returned_uid = _extract_detail_user_row_id(detail)
        if not returned_uid or returned_uid.lower() != user_id.lower():
            raise BoncAuthUnavailableError(
                "BONC getUserDetail answered for a different user than the token names."
            )

        if _is_user_detail_inactive(detail):
            raise BoncTokenInvalidError("This BONC account is deactivated.")

        matched_roles: list[str] = []
        seen_lower: set[str] = set()
        for raw_role in extract_user_detail_roles(detail):
            key = raw_role.lower()
            if key in self.admin_roles and key not in seen_lower:
                seen_lower.add(key)
                matched_roles.append(self.admin_roles[key])
        if not matched_roles:
            raise BoncAuthorizationDeniedError("Administrator access required.")

        return VerifiedBoncIdentity(
            user_id=returned_uid,
            username=_extract_optional_display_username(detail),
            expires_at_utc=None,
            roles=tuple(matched_roles),
            session_id=None,
        )


class CachedBoncTokenVerifier(BoncTokenVerifier):
    """Thread-safe TTL cache storing ONLY successful ``VerifiedBoncIdentity`` results.

    Keys are SHA-256 hex digests of the raw token so raw tokens are never held
    as cache keys. Rejections (401/403) and upstream failures (503) are never
    cached. Setting ``ttl=0`` disables caching cleanly.
    """

    MAX_ENTRIES = 2000

    def __init__(
        self,
        inner: BoncTokenVerifier,
        ttl: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(float(ttl)) or float(ttl) < 0:
            raise ValueError("ttl must be greater than or equal to zero.")
        self._inner = inner
        self._ttl = float(ttl)
        self._clock = clock
        self._seen: dict[str, tuple[float, VerifiedBoncIdentity]] = {}
        self._lock = threading.Lock()

    @property
    def inner(self) -> BoncTokenVerifier:
        return self._inner

    @property
    def ttl(self) -> float:
        return self._ttl

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()

    def is_configured(self) -> bool:
        return self._inner.is_configured()

    def verify_access_token(self, raw_token: str) -> VerifiedBoncIdentity:
        if self._ttl <= 0:
            return self._inner.verify_access_token(raw_token)
        key = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        now = self._clock()
        with self._lock:
            hit = self._seen.get(key)
            if hit is not None:
                if hit[0] > now:
                    return hit[1]
                self._seen.pop(key, None)

        identity = self._inner.verify_access_token(raw_token)  # raises on refusal: never cached
        with self._lock:
            if len(self._seen) >= self.MAX_ENTRIES:
                self._seen = {k: v for k, v in self._seen.items() if v[0] > now}
                if len(self._seen) >= self.MAX_ENTRIES:
                    self._seen.clear()
            self._seen[key] = (now + self._ttl, identity)
        return identity


class BoncUserDetailVerifierAdapter(BoncTokenVerifier):
    """``BoncTokenVerifier`` adapter backed by BONC's ``getUserDetail`` endpoint."""

    def __init__(self, client: UserDetailAuth | None = None) -> None:
        self._client = client

    @property
    def client(self) -> UserDetailAuth | None:
        return self._client

    @classmethod
    def from_settings(
        cls,
        *,
        verify_url: str,
        admin_roles: Iterable[str],
        timeout: float = 5.0,
        service_headers: Mapping[str, str] | None = None,
    ) -> BoncUserDetailVerifierAdapter:
        client = UserDetailAuth(
            verify_url,
            admin_roles=admin_roles,
            timeout=timeout,
            service_headers=service_headers,
        )
        return cls(client=client)

    def is_configured(self) -> bool:
        return self._client is not None

    def verify_access_token(self, raw_token: str) -> VerifiedBoncIdentity:
        if self._client is None:
            raise BoncAuthNotConfiguredError("BONC authentication verifier is not configured")
        return self._client.verify(raw_token)


def build_bonc_user_detail_provider(
    *,
    verify_url: str,
    admin_roles: Iterable[str] = ("Admin", "SuperAdmin"),
    timeout: float = 5.0,
    cache_seconds: float = 60.0,
    clock: Callable[[], float] = time.monotonic,
) -> BoncJwtAuthProvider:
    """Build the configured BONC ``getUserDetail`` ``BoncJwtAuthProvider``."""
    cleaned_roles = tuple(
        dict.fromkeys(r.strip() for r in admin_roles if isinstance(r, str) and r.strip())
    )
    if not cleaned_roles:
        raise ValueError(
            "BONC_AUTH_ADMIN_ROLES must include at least one role "
            "(e.g. Admin,SuperAdmin): with none, nobody could ever get in"
        )

    ttl = float(cache_seconds)
    if not math.isfinite(ttl) or ttl < 0:
        raise ValueError(f"BONC_AUTH_CACHE_SECONDS must be >= 0, not {cache_seconds!r}")

    verifier: BoncTokenVerifier = BoncUserDetailVerifierAdapter.from_settings(
        verify_url=verify_url,
        admin_roles=cleaned_roles,
        timeout=timeout,
    )
    if ttl > 0:
        verifier = CachedBoncTokenVerifier(verifier, ttl=ttl, clock=clock)

    return BoncJwtAuthProvider(
        verifier=verifier,
        claims_config=BoncClaimsValidationConfig.delegated_server_verification(),
        role_policy=BoncRoleAuthorizationPolicy(allowed_admin_roles=frozenset(cleaned_roles)),
    )
