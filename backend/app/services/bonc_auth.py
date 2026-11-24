"""BONC JWT authentication provider, strict Bearer extraction, claim invariants, and RBAC.

Design principles:
- BONC is the ONLY supported Search Admin user authentication system.
  Search_Admin never generates, signs, or refreshes BONC tokens, never offers
  local username/password login, never accepts cookie sessions or unrelated
  static/observability tokens, and has no authentication-disable bypass.
- Authentication and authorization are strictly separated:
  1. ``BoncTokenVerifier`` verifies the incoming Bearer token via BONC's
     authoritative ``getUserDetail`` endpoint (``BoncUserDetailVerifier``).
  2. ``validate_verified_bonc_identity`` enforces identity invariants on the
     verified result.
  3. ``BoncRoleAuthorizationPolicy`` maps verified BONC admin roles to explicit
     Search_Admin capabilities and denies non-Admin BONC users with HTTP 403.
- Fails closed with HTTP 503 if ``BONC_AUTH_VERIFY_URL`` is unconfigured or if
  BONC's endpoint is unreachable or returns an unexpected response.
"""
from __future__ import annotations

import hmac
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal

from fastapi import HTTPException, Request

from app.logger import logger

# ---------------------------------------------------------------------------
# Search_Admin explicit capability / permission scope
# ---------------------------------------------------------------------------

ADMIN_PERMISSION_HEALTH_READ = "admin:health:read"
ADMIN_PERMISSION_CATEGORIES_READ = "admin:categories:read"
ADMIN_PERMISSION_CATEGORIES_WRITE = "admin:categories:write"
ADMIN_PERMISSION_SOURCES_READ = "admin:sources:read"
ADMIN_PERMISSION_INGESTION_WRITE = "admin:ingestion:write"
ADMIN_PERMISSION_LOGS_READ = "admin:logs:read"
ADMIN_PERMISSION_ANALYTICS_READ = "admin:analytics:read"
ADMIN_PERMISSION_SEARCH_EXECUTE = "admin:search:execute"
ADMIN_PERMISSION_PRODUCTION_READ = "admin:production:read"

ALL_ADMIN_PERMISSIONS: frozenset[str] = frozenset(
    {
        ADMIN_PERMISSION_HEALTH_READ,
        ADMIN_PERMISSION_CATEGORIES_READ,
        ADMIN_PERMISSION_CATEGORIES_WRITE,
        ADMIN_PERMISSION_SOURCES_READ,
        ADMIN_PERMISSION_INGESTION_WRITE,
        ADMIN_PERMISSION_LOGS_READ,
        ADMIN_PERMISSION_ANALYTICS_READ,
        ADMIN_PERMISSION_SEARCH_EXECUTE,
        ADMIN_PERMISSION_PRODUCTION_READ,
    }
)

_MAX_BEARER_TOKEN_LENGTH = 8192
_MAX_CLOCK_SKEW_SECONDS = 60

# Separate backend/observability secrets that must NEVER be accepted as BONC user tokens.
_FORBIDDEN_NON_BONC_TOKEN_ENV_KEYS = (
    "PRODUCTION_SEARCH_AUTH_TOKEN",
    "SEARCH_ADMIN_API_TOKEN",
    "SEARCH_INTERNAL_API_TOKEN",
)


# ---------------------------------------------------------------------------
# Shared Principal & Provider abstractions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdminPrincipal:
    """Trusted identity & authorization context attached to authenticated Admin requests."""

    actor: str
    username: str
    auth_method: Literal["bonc_jwt"] = "bonc_jwt"
    roles: tuple[str, ...] = ()
    session_id: str | None = None
    expires_at_utc: datetime | None = None
    user_id: str | None = None
    permissions: tuple[str, ...] = ()
    token_id: str | None = None


def attach_request_principal(request: Request | None, principal: AdminPrincipal) -> None:
    """Attach verified identity attributes to ``request.state`` for observability & audit."""
    if request is None:
        return
    request.state.authenticated_user_id = principal.actor
    request.state.identity_type = "authenticated"
    request.state.admin_auth_method = principal.auth_method
    request.state.admin_session_id = principal.session_id
    request.state.admin_roles = principal.roles
    request.state.admin_permissions = principal.permissions
    request.state.admin_user_id = principal.user_id


def _mark_request_auth_failed(request: Request | None) -> None:
    """Record failed admin auth on ``request.state`` so observability logging never re-verifies."""
    if request is None:
        return
    if getattr(request.state, "identity_type", None) not in {"authenticated", "anonymous", "session"}:
        request.state.identity_type = "anonymous"
        request.state.authenticated_user_id = None


class AdminAuthProvider(ABC):
    """Abstract authentication provider decoupled from Search_Admin routes."""

    @property
    def auth_mode(self) -> str:
        return "bonc_jwt"

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if the provider has sufficient server-side configuration."""

    @abstractmethod
    def authorize_request(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
    ) -> AdminPrincipal:
        """Validate caller identity and return a trusted ``AdminPrincipal``."""

    def authorize_permission(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
        required_permission: str | None = None,
    ) -> AdminPrincipal:
        """Authorize a request and verify an optional fine-grained Search_Admin permission."""
        principal = self.authorize_request(request, authorization=authorization)
        if (
            required_permission
            and principal.permissions
            and required_permission not in principal.permissions
        ):
            raise HTTPException(
                status_code=403,
                detail="Insufficient administrator permissions",
                headers={"X-Auth-Mode": self.auth_mode},
            )
        return principal

    def try_authenticate_public_request(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
    ) -> str | None:
        """Optionally resolve a verified user ID on public endpoints without failing closed.

        Returns ``None`` if no valid credentials were provided or if the provider
        is not configured. NEVER trusts unverified tokens or client headers.
        """
        return None


# ---------------------------------------------------------------------------
# Typed BONC authentication & authorization exceptions
# ---------------------------------------------------------------------------


class BoncAuthNotConfiguredError(RuntimeError):
    """Raised when BONC token verification or role mapping is not configured."""


class BoncAuthUnavailableError(RuntimeError):
    """Raised when BONC verification is unreachable or returns an unexpected response."""


class BoncTokenExtractionError(ValueError):
    """Raised when the Authorization header is missing, malformed, or uses a wrong scheme."""


class BoncTokenInvalidError(ValueError):
    """Raised when a BONC access token is invalid, expired, revoked, or belongs to an inactive user."""


class BoncAuthorizationDeniedError(PermissionError):
    """Raised when an authenticated BONC identity lacks required Search_Admin permissions."""


# ---------------------------------------------------------------------------
# Strict Bearer token extraction
# ---------------------------------------------------------------------------


def _utc_now_naive() -> datetime:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def _normalize_utc_naive(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def extract_bearer_token(authorization: str | None) -> str:
    """Strictly extract ``<AuthToken>`` from ``Authorization: Bearer <AuthToken>``.

    Rejects missing headers, non-Bearer schemes, empty tokens, extra whitespace
    segments, control characters, oversized tokens, and non-ASCII characters.
    """
    if not isinstance(authorization, str):
        raise BoncTokenExtractionError("Missing Authorization header")

    trimmed = authorization.strip()
    if not trimmed:
        raise BoncTokenExtractionError("Empty Authorization header")

    if any(ord(ch) < 32 or ord(ch) >= 127 for ch in trimmed):
        raise BoncTokenExtractionError("Malformed Authorization header")

    parts = trimmed.split()
    if len(parts) != 2:
        raise BoncTokenExtractionError("Malformed Authorization header")

    scheme, token = parts[0], parts[1]
    if scheme.lower() != "bearer":
        raise BoncTokenExtractionError("Unsupported Authorization scheme")

    if not token or len(token) > _MAX_BEARER_TOKEN_LENGTH:
        raise BoncTokenExtractionError("Invalid Bearer token length")

    return token


# ---------------------------------------------------------------------------
# Verified BONC identity, claims policy, verifier contract & role policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedBoncIdentity:
    """Trusted identity returned ONLY after authoritative BONC server-side verification."""

    user_id: str
    username: str | None
    expires_at_utc: datetime | None
    issuer: str | None = None
    audience: str | tuple[str, ...] | None = None
    not_before_utc: datetime | None = None
    issued_at_utc: datetime | None = None
    algorithm: str | None = None
    key_id: str | None = None
    token_type: str | None = None
    token_id: str | None = None
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    session_id: str | None = None


@dataclass(frozen=True)
class BoncClaimsValidationConfig:
    """Server-side validation rules for verified BONC identities.

    When ``delegated_token_validation=True`` (used for BONC's authoritative
    ``getUserDetail`` endpoint), signature, expiry, and revocation checks are
    performed remotely by BONC .NET while Search_Admin still enforces a valid
    ``user_id`` and validates any optional timestamps if present.
    """

    allowed_algorithms: frozenset[str] = frozenset()
    expected_issuer: str = ""
    expected_audience: str = ""
    allowed_key_ids: frozenset[str] | None = None
    expected_token_type: str | None = None
    clock_skew_seconds: int = 0
    require_algorithm: bool = True
    delegated_token_validation: bool = False

    @classmethod
    def delegated_server_verification(
        cls,
        *,
        clock_skew_seconds: int = 0,
    ) -> BoncClaimsValidationConfig:
        """Build a claims config for authoritative .NET ``getUserDetail`` verification."""
        return cls(
            allowed_algorithms=frozenset(),
            expected_issuer="",
            expected_audience="",
            clock_skew_seconds=clock_skew_seconds,
            require_algorithm=False,
            delegated_token_validation=True,
        )

    def is_valid(self) -> bool:
        if not (0 <= int(self.clock_skew_seconds) <= _MAX_CLOCK_SKEW_SECONDS):
            return False
        if self.delegated_token_validation:
            return True
        if not self.expected_issuer or not self.expected_issuer.strip():
            return False
        if not self.expected_audience or not self.expected_audience.strip():
            return False
        if self.require_algorithm:
            if not self.allowed_algorithms:
                return False
            if any(not a.strip() or a.strip().lower() == "none" for a in self.allowed_algorithms):
                return False
        return True


def validate_verified_bonc_identity(
    identity: VerifiedBoncIdentity,
    config: BoncClaimsValidationConfig,
    *,
    now_utc: datetime | None = None,
) -> VerifiedBoncIdentity:
    """Enforce defense-in-depth identity invariants on an already-verified BONC identity."""
    if not config.is_valid():
        raise BoncAuthNotConfiguredError("BONC claims validation configuration is incomplete")

    user_id = (identity.user_id or "").strip() if isinstance(identity.user_id, str) else ""
    if not user_id or len(user_id) > 256:
        raise BoncTokenInvalidError("Verified BONC token is missing a valid user identifier")

    if not config.delegated_token_validation and config.require_algorithm:
        alg = (identity.algorithm or "").strip() if isinstance(identity.algorithm, str) else ""
        if not alg or alg.lower() == "none" or alg not in config.allowed_algorithms:
            raise BoncTokenInvalidError("Verified BONC token algorithm is not allowed")

    if config.allowed_key_ids is not None:
        kid = (identity.key_id or "").strip() if isinstance(identity.key_id, str) else ""
        if not kid or kid not in config.allowed_key_ids:
            raise BoncTokenInvalidError("Verified BONC token key ID (kid) is not trusted")

    if config.expected_token_type is not None:
        typ = (identity.token_type or "").strip() if isinstance(identity.token_type, str) else ""
        if not typ or typ.lower() != config.expected_token_type.strip().lower():
            raise BoncTokenInvalidError("Verified BONC token type constraint failed")

    issuer: str | None = (
        identity.issuer.strip() if isinstance(identity.issuer, str) and identity.issuer.strip() else None
    )
    if not config.delegated_token_validation or config.expected_issuer.strip():
        if not issuer or issuer != config.expected_issuer.strip():
            raise BoncTokenInvalidError("Verified BONC token issuer mismatch")

    expected_aud = config.expected_audience.strip()
    if isinstance(identity.audience, str):
        aud_values: tuple[str, ...] | None = (
            (identity.audience.strip(),) if identity.audience.strip() else ()
        )
    elif isinstance(identity.audience, tuple):
        aud_values = tuple(a.strip() for a in identity.audience if isinstance(a, str) and a.strip())
    else:
        aud_values = () if not config.delegated_token_validation else None
    if not config.delegated_token_validation or expected_aud:
        if not aud_values or expected_aud not in aud_values:
            raise BoncTokenInvalidError("Verified BONC token audience mismatch")

    now = _normalize_utc_naive(now_utc) or _utc_now_naive()
    skew = timedelta(seconds=int(config.clock_skew_seconds))

    expires_at = _normalize_utc_naive(identity.expires_at_utc)
    if not config.delegated_token_validation:
        if expires_at is None:
            raise BoncTokenInvalidError("Verified BONC token is missing expiration (exp)")
        if expires_at <= (now - skew):
            raise BoncTokenInvalidError("Verified BONC token has expired")
    elif expires_at is not None and expires_at <= (now - skew):
        raise BoncTokenInvalidError("Verified BONC token has expired")

    not_before = _normalize_utc_naive(identity.not_before_utc)
    if not_before is not None and not_before > (now + skew):
        raise BoncTokenInvalidError("Verified BONC token is not yet valid (nbf)")

    cleaned_roles = tuple(
        r.strip() for r in identity.roles if isinstance(r, str) and r.strip()
    )
    cleaned_perms = tuple(
        p.strip() for p in identity.permissions if isinstance(p, str) and p.strip()
    )
    cleaned_username = (
        identity.username.strip()[:256]
        if isinstance(identity.username, str) and identity.username.strip()
        else None
    )

    return VerifiedBoncIdentity(
        user_id=user_id,
        username=cleaned_username,
        expires_at_utc=expires_at,
        issuer=issuer,
        audience=aud_values,
        not_before_utc=not_before,
        issued_at_utc=_normalize_utc_naive(identity.issued_at_utc),
        algorithm=identity.algorithm,
        key_id=identity.key_id,
        token_type=identity.token_type,
        token_id=(
            identity.token_id.strip()[:128]
            if isinstance(identity.token_id, str) and identity.token_id.strip()
            else None
        ),
        roles=cleaned_roles,
        permissions=cleaned_perms,
        session_id=(
            identity.session_id.strip()[:128]
            if isinstance(identity.session_id, str) and identity.session_id.strip()
            else None
        ),
    )


class BoncTokenVerifier(ABC):
    """Abstract verification adapter backed by BONC's ``getUserDetail`` endpoint."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True only when all required BONC verification settings are present."""

    @abstractmethod
    def verify_access_token(self, raw_token: str) -> VerifiedBoncIdentity:
        """Verify ``raw_token`` and return a trusted ``VerifiedBoncIdentity``."""


AuthorizationResolver = Callable[
    [VerifiedBoncIdentity],
    tuple[tuple[str, ...], tuple[str, ...]],
]


@dataclass(frozen=True)
class BoncRoleAuthorizationPolicy:
    """Explicit mapping from verified BONC roles/permissions to Search_Admin capabilities.

    Never grants Admin access to ordinary (e.g. ``Basic``) BONC users. Fails
    closed with ``BoncAuthNotConfiguredError`` unless explicit role/permission
    mappings are configured.
    """

    allowed_admin_roles: frozenset[str] = frozenset()
    role_permission_map: dict[str, frozenset[str]] | None = None
    allowed_permissions_direct: frozenset[str] = frozenset()
    authorization_resolver: AuthorizationResolver | None = None

    def is_configured(self) -> bool:
        has_admin_roles = any(r.strip() for r in self.allowed_admin_roles)
        has_role_map = bool(
            self.role_permission_map
            and any(
                k.strip() and bool(v)
                for k, v in self.role_permission_map.items()
            )
        )
        has_direct_perms = any(p.strip() for p in self.allowed_permissions_direct)
        return has_admin_roles or has_role_map or has_direct_perms

    def authorize(
        self,
        identity: VerifiedBoncIdentity,
        *,
        required_permission: str | None = None,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Resolve effective ``(roles, permissions)`` or deny fail-closed."""
        if not self.is_configured():
            raise BoncAuthNotConfiguredError("BONC Admin authorization policy is not configured")

        effective_roles = identity.roles
        effective_source_perms = identity.permissions
        if self.authorization_resolver is not None:
            resolved_roles, resolved_perms = self.authorization_resolver(identity)
            effective_roles = tuple(
                r.strip() for r in resolved_roles if isinstance(r, str) and r.strip()
            )
            effective_source_perms = tuple(
                p.strip() for p in resolved_perms if isinstance(p, str) and p.strip()
            )

        if not effective_roles and not effective_source_perms:
            raise BoncAuthorizationDeniedError("Administrator access required")

        normalized_admin_roles = {r.strip().lower() for r in self.allowed_admin_roles if r.strip()}
        normalized_role_map = {
            k.strip().lower(): frozenset(v)
            for k, v in (self.role_permission_map or {}).items()
            if k.strip() and v
        }
        normalized_direct_perms = {
            p.strip().lower() for p in self.allowed_permissions_direct if p.strip()
        }

        granted: set[str] = set()
        for role in effective_roles:
            key = role.strip().lower()
            if key in normalized_admin_roles:
                granted.update(ALL_ADMIN_PERMISSIONS)
            if key in normalized_role_map:
                granted.update(normalized_role_map[key])

        for perm in effective_source_perms:
            if perm.strip().lower() in normalized_direct_perms and perm in ALL_ADMIN_PERMISSIONS:
                granted.add(perm)

        if not granted:
            raise BoncAuthorizationDeniedError("Administrator access required")

        if required_permission and required_permission not in granted:
            raise BoncAuthorizationDeniedError("Insufficient administrator permissions")

        return effective_roles, tuple(sorted(granted))


# ---------------------------------------------------------------------------
# BoncJwtAuthProvider (Sole Search Admin Authentication Provider)
# ---------------------------------------------------------------------------


def _matches_env_secret(candidate: str, env_name: str) -> bool:
    expected = os.getenv(env_name, "").strip()
    if not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


class BoncJwtAuthProvider(AdminAuthProvider):
    """Mandatory BONC Bearer access-token authentication & Admin authorization provider.

    Fails closed (HTTP 503) if ``verifier``, ``claims_config``, or ``role_policy``
    is unconfigured. Never falls back to local logins, cookies, or static tokens.
    """

    def __init__(
        self,
        *,
        verifier: BoncTokenVerifier | None = None,
        claims_config: BoncClaimsValidationConfig | None = None,
        role_policy: BoncRoleAuthorizationPolicy | None = None,
        now_provider: Callable[[], datetime] | None = None,
    ) -> None:
        self._verifier = verifier
        self._claims_config = claims_config
        self._role_policy = role_policy
        self._now_provider = now_provider

    @property
    def auth_mode(self) -> str:
        return "bonc_jwt"

    def is_configured(self) -> bool:
        return bool(
            self._verifier is not None
            and self._verifier.is_configured()
            and self._claims_config is not None
            and self._claims_config.is_valid()
            and self._role_policy is not None
            and self._role_policy.is_configured()
        )

    def _extract_raw_header(
        self,
        request: Request | None,
        authorization: str | None,
    ) -> str | None:
        if authorization is not None:
            return authorization
        if request is not None:
            return request.headers.get("authorization")
        return None

    def authenticate_bonc_user(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
    ) -> VerifiedBoncIdentity:
        """Authenticate a BONC user Bearer token (separate from Admin authorization)."""
        if (
            self._verifier is None
            or not self._verifier.is_configured()
            or self._claims_config is None
            or not self._claims_config.is_valid()
        ):
            raise BoncAuthNotConfiguredError("BONC authentication is not configured")

        raw_header = self._extract_raw_header(request, authorization)
        raw_token = extract_bearer_token(raw_header)

        # Reject known non-BONC/observability secrets explicitly before calling BONC .NET.
        for env_key in _FORBIDDEN_NON_BONC_TOKEN_ENV_KEYS:
            if _matches_env_secret(raw_token, env_key):
                raise BoncTokenInvalidError("Non-BONC service token cannot authenticate a BONC user")

        verified = self._verifier.verify_access_token(raw_token)
        now = self._now_provider() if self._now_provider is not None else None
        return validate_verified_bonc_identity(verified, self._claims_config, now_utc=now)

    def authorize_request(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
    ) -> AdminPrincipal:
        return self.authorize_permission(
            request,
            authorization=authorization,
            required_permission=None,
        )

    def authorize_permission(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
        required_permission: str | None = None,
    ) -> AdminPrincipal:
        # Fail closed with 503 if verifier, claims validation, or Admin role mapping is unconfigured.
        if not self.is_configured():
            _mark_request_auth_failed(request)
            raise HTTPException(
                status_code=503,
                detail="BONC authentication is not configured",
                headers={"X-Auth-Mode": self.auth_mode},
            )

        try:
            identity = self.authenticate_bonc_user(request, authorization=authorization)
            assert self._role_policy is not None
            effective_roles, granted_permissions = self._role_policy.authorize(
                identity,
                required_permission=required_permission,
            )
        except BoncAuthNotConfiguredError as exc:
            _mark_request_auth_failed(request)
            raise HTTPException(
                status_code=503,
                detail=str(exc) or "BONC authentication is not configured",
                headers={"X-Auth-Mode": self.auth_mode},
            ) from exc
        except BoncAuthUnavailableError as exc:
            _mark_request_auth_failed(request)
            logger.warning(
                "BONC authentication service unavailable (exception_type=%s)",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail="BONC authentication service is unavailable",
                headers={"X-Auth-Mode": self.auth_mode},
            ) from exc
        except (BoncTokenExtractionError, BoncTokenInvalidError) as exc:
            _mark_request_auth_failed(request)
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={
                    "WWW-Authenticate": "Bearer",
                    "X-Auth-Mode": self.auth_mode,
                },
            ) from exc
        except BoncAuthorizationDeniedError as exc:
            _mark_request_auth_failed(request)
            raise HTTPException(
                status_code=403,
                detail=str(exc) or "Administrator access required",
                headers={"X-Auth-Mode": self.auth_mode},
            ) from exc
        except HTTPException:
            _mark_request_auth_failed(request)
            raise
        except Exception as exc:
            _mark_request_auth_failed(request)
            logger.error(
                "Unexpected BONC authentication error (exception_type=%s)",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail="BONC authentication service is unavailable",
                headers={"X-Auth-Mode": self.auth_mode},
            ) from exc

        # Prefer stable BONC UserRowId for audit identity (UpdatedBy, ChangedBy, SearchLogs).
        actor = identity.user_id[:256]
        display_username = identity.username or identity.user_id

        principal = AdminPrincipal(
            actor=actor,
            username=display_username,
            auth_method="bonc_jwt",
            roles=effective_roles,
            permissions=granted_permissions,
            user_id=identity.user_id,
            session_id=identity.session_id,
            expires_at_utc=identity.expires_at_utc,
            token_id=identity.token_id,
        )
        attach_request_principal(request, principal)
        return principal

    def try_authenticate_public_request(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
    ) -> str | None:
        """Optionally attribute a verified BONC user ID on public search endpoints."""
        if (
            self._verifier is None
            or not self._verifier.is_configured()
            or self._claims_config is None
            or not self._claims_config.is_valid()
        ):
            return None
        raw_header = self._extract_raw_header(request, authorization)
        if not isinstance(raw_header, str) or not raw_header.strip():
            return None
        try:
            identity = self.authenticate_bonc_user(request, authorization=authorization)
            return identity.user_id[:256]
        except Exception:
            return None
