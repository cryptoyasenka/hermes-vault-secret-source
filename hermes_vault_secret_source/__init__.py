"""HashiCorp Vault as a Hermes Agent secret source.

Bulk KV v2 source: reads one Vault KV v2 secret path and contributes its
keys as environment variables at Hermes startup, mirroring how the bundled
Bitwarden Secrets Manager source injects a whole project.

Registered through the ``hermes_agent.plugins`` entry point (see
pyproject.toml): Hermes' plugin loader imports this package and calls
``register(ctx)``.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import FrozenSet

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
)

from . import _client

__all__ = ["VaultSource", "register"]

_DEFAULT_ADDR_ENV = "VAULT_ADDR"
_DEFAULT_TOKEN_ENV = "VAULT_TOKEN"
_DEFAULT_ROLE_ID_ENV = "VAULT_ROLE_ID"
_DEFAULT_SECRET_ID_ENV = "VAULT_SECRET_ID"
_DEFAULT_MOUNT_POINT = "secret"
_DEFAULT_CACHE_TTL_SECONDS = 300.0
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0


class VaultSource(SecretSource):
    """HashiCorp Vault KV v2 as a registered secret source.

    Thin adapter over :func:`_client.fetch_vault_secrets`. ``fetch()`` only
    resolves values; precedence, override semantics, conflict warnings and
    the actual ``os.environ`` writes belong to the orchestrator
    (``agent.secret_sources.registry.apply_all``).

    Vault is a **bulk** source: it injects every key found at the configured
    KV v2 path, so explicit per-var bindings from mapped sources outrank it.
    """

    name = "vault"
    label = "HashiCorp Vault"
    shape = "bulk"
    scheme = "vault"

    def override_existing(self, cfg: dict) -> bool:
        # Default True: the point of a central vault is rotation. If .env had
        # the final say, rotating a key in Vault would not take effect until
        # the stale .env line was also removed.
        return bool(isinstance(cfg, dict) and cfg.get("override_existing", True))

    def protected_env_vars(self, cfg: dict) -> FrozenSet[str]:
        cfg = cfg if isinstance(cfg, dict) else {}
        names = {
            str(cfg.get("addr_env") or _DEFAULT_ADDR_ENV),
            str(cfg.get("token_env") or _DEFAULT_TOKEN_ENV),
            str(cfg.get("role_id_env") or _DEFAULT_ROLE_ID_ENV),
            str(cfg.get("secret_id_env") or _DEFAULT_SECRET_ID_ENV),
        }
        # A vault that stores its own VAULT_TOKEN must never clobber the
        # credential used to reach it. The orchestrator also requires valid
        # env-var names, so drop anything a misconfigured section produced.
        return frozenset(n for n in names if is_valid_env_name(n))

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "addr": {
                "description": "Vault server URL (overrides addr_env when set)",
                "default": "",
            },
            "addr_env": {
                "description": "Env var holding the Vault server URL",
                "default": _DEFAULT_ADDR_ENV,
            },
            "path": {
                "description": "KV v2 secret path whose keys become env vars",
                "default": "",
            },
            "mount_point": {
                "description": "KV v2 secrets-engine mount point",
                "default": _DEFAULT_MOUNT_POINT,
            },
            "auth_method": {
                "description": "How to authenticate: 'token' or 'approle'",
                "default": "token",
            },
            "token_env": {
                "description": "Env var holding the Vault token (auth_method=token)",
                "default": _DEFAULT_TOKEN_ENV,
            },
            "role_id_env": {
                "description": "Env var holding the AppRole role_id (auth_method=approle)",
                "default": _DEFAULT_ROLE_ID_ENV,
            },
            "secret_id_env": {
                "description": "Env var holding the AppRole secret_id (auth_method=approle)",
                "default": _DEFAULT_SECRET_ID_ENV,
            },
            "namespace": {
                "description": "Vault Enterprise namespace (empty for OSS)",
                "default": "",
            },
            "verify": {
                "description": "TLS verify: true/false or a CA-bundle path",
                "default": True,
            },
            "cache_ttl_seconds": {
                "description": "Disk+memory cache TTL; 0 disables caching",
                "default": 300,
            },
            "request_timeout_seconds": {
                "description": "Per-request Vault HTTP timeout in seconds",
                "default": 30,
            },
            "override_existing": {
                "description": "Vault values overwrite .env/shell values",
                "default": True,
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        result = FetchResult()

        addr_env = str(cfg.get("addr_env") or _DEFAULT_ADDR_ENV)
        addr = str(cfg.get("addr") or os.environ.get(addr_env, "") or "").strip()
        if not addr:
            result.error = (
                "secrets.vault is enabled but no Vault address is set "
                f"(set {addr_env} or secrets.vault.addr)."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        path = str(cfg.get("path") or "").strip()
        if not path:
            result.error = (
                "secrets.vault.path is empty (the KV v2 path whose keys are "
                "injected as environment variables)."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        auth_method = str(cfg.get("auth_method") or "token").strip().lower()
        token = role_id = secret_id = ""
        if auth_method == "token":
            token_env = str(cfg.get("token_env") or _DEFAULT_TOKEN_ENV)
            token = os.environ.get(token_env, "").strip()
            if not token:
                result.error = (
                    f"secrets.vault auth_method is 'token' but {token_env} is not set."
                )
                result.error_kind = ErrorKind.NOT_CONFIGURED
                return result
        elif auth_method == "approle":
            role_id_env = str(cfg.get("role_id_env") or _DEFAULT_ROLE_ID_ENV)
            secret_id_env = str(cfg.get("secret_id_env") or _DEFAULT_SECRET_ID_ENV)
            role_id = os.environ.get(role_id_env, "").strip()
            secret_id = os.environ.get(secret_id_env, "").strip()
            if not role_id or not secret_id:
                result.error = (
                    "secrets.vault auth_method is 'approle' but "
                    f"{role_id_env} and {secret_id_env} are not both set."
                )
                result.error_kind = ErrorKind.NOT_CONFIGURED
                return result
        else:
            result.error = (
                f"secrets.vault.auth_method {auth_method!r} is not supported "
                "(use 'token' or 'approle')."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        mount_point = (
            str(cfg.get("mount_point") or _DEFAULT_MOUNT_POINT).strip()
            or _DEFAULT_MOUNT_POINT
        )
        namespace = str(cfg.get("namespace") or "").strip() or None
        verify = _coerce_verify(cfg.get("verify", True))
        ttl = _coerce_float(
            cfg.get("cache_ttl_seconds", _DEFAULT_CACHE_TTL_SECONDS),
            _DEFAULT_CACHE_TTL_SECONDS,
            allow_zero=True,
        )
        timeout = _coerce_float(
            cfg.get("request_timeout_seconds", _DEFAULT_REQUEST_TIMEOUT_SECONDS),
            _DEFAULT_REQUEST_TIMEOUT_SECONDS,
            allow_zero=False,
        )

        try:
            secrets, warnings = _client.fetch_vault_secrets(
                addr=addr,
                path=path,
                mount_point=mount_point,
                namespace=namespace,
                verify=verify,
                timeout=timeout,
                auth_method=auth_method,
                token=token,
                role_id=role_id,
                secret_id=secret_id,
                cache_ttl_seconds=ttl,
                home_path=home_path,
            )
        except RuntimeError as exc:
            result.error = str(exc)
            result.error_kind = _classify_vault_error(str(exc))
            return result

        result.secrets = secrets
        result.warnings.extend(warnings)
        return result


def _coerce_float(value, default: float, *, allow_zero: bool) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    if out < 0 or (out == 0 and not allow_zero):
        return default
    return out


def _coerce_verify(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("false", "0", "no", "off"):
            return False
        if low in ("true", "1", "yes", "on"):
            return True
        return value.strip()  # otherwise treat it as a CA-bundle path
    return True


def _classify_vault_error(message: str) -> ErrorKind:
    """Best-effort mapping of a backend failure onto the shared taxonomy."""
    lowered = message.lower()
    if "not installed" in lowered:
        return ErrorKind.BINARY_MISSING
    if "timed out" in lowered or "timeout" in lowered:
        return ErrorKind.TIMEOUT
    if any(tok in lowered for tok in (
        "forbidden", "permission denied", "invalid request",
        "credentials rejected", "401", "403",
    )):
        return ErrorKind.AUTH_FAILED
    if any(tok in lowered for tok in ("invalidpath", "not found", "404")):
        return ErrorKind.REF_INVALID
    if any(tok in lowered for tok in (
        "connection", "network", "refused", "unreachable",
        "resolve", "dns", "failed to create",
    )):
        return ErrorKind.NETWORK
    return ErrorKind.INTERNAL


def register(ctx) -> None:
    """Entry point invoked by Hermes' plugin loader.

    ``ctx`` is the PluginContext; it validates the instance and hands it to
    the secret-source registry.
    """
    ctx.register_secret_source(VaultSource())
