"""HashiCorp Vault backend: fetch + two-layer cache (hvac, KV v2, bulk).

Mirrors the security posture of the bundled Bitwarden/1Password sources:
this module only *reads* secrets and raises ``RuntimeError`` on any failure.
The :class:`~hermes_vault_secret_source.VaultSource` adapter turns that into
a ``FetchResult`` so nothing ever escapes onto the Hermes startup path.

``hvac`` is imported lazily inside :func:`_read_kv2` so that importing this
module (and running the conformance suite) never requires the dependency;
only an actually-configured fetch touches Vault.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent.secret_sources.base import is_valid_env_name

# The shared on-disk cache substrate is re-exported by the host for backends.
# If a host ships without it we degrade to no caching rather than fail import.
try:
    from agent.secret_sources._cache import CachedFetch, DiskCache
except Exception:  # pragma: no cover - only on an incompatible host
    CachedFetch = None  # type: ignore[assignment,misc]
    DiskCache = None  # type: ignore[assignment,misc]


def _serialize_cache_key(key) -> str:
    # json, not "|".join: a literal "|" inside path/namespace must not collapse
    # two distinct keys onto the same disk-cache slot (which would serve one
    # token's secrets under another's key).
    return json.dumps([str(part) for part in key], separators=(",", ":"))


_CACHE: Dict[tuple, "CachedFetch"] = {}
_DISK_CACHE = (
    DiskCache("vault_cache.json", key_serializer=_serialize_cache_key)
    if DiskCache is not None
    else None
)


def _fingerprint(value: str) -> str:
    """SHA-256 prefix of auth material, used only inside cache keys.

    The on-disk cache stores secret *values*; the token/secret_id must never
    reach it in the clear, so it is fingerprinted before it enters the key.
    """
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:16]


def fetch_vault_secrets(
    *,
    addr: str,
    path: str,
    mount_point: str = "secret",
    namespace: Optional[str] = None,
    verify=True,
    timeout: float = 30.0,
    auth_method: str = "token",
    token: str = "",
    role_id: str = "",
    secret_id: str = "",
    cache_ttl_seconds: float = 300.0,
    use_cache: bool = True,
    home_path: Optional[Path] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Read one KV v2 path and return ``(env_name -> value, warnings)``.

    Raises ``RuntimeError`` on any fatal condition (hvac missing, auth
    failure, network error, bad path, unexpected shape). The caller in
    ``__init__.py`` catches this and classifies it onto an ``ErrorKind``.
    """
    if auth_method == "approle":
        # json-encode, not delimiter-concat: a colon inside role_id/secret_id
        # must not let two different credential pairs fingerprint identically.
        auth_fp = _fingerprint(json.dumps(["approle", role_id, secret_id]))
    else:
        auth_fp = _fingerprint(json.dumps(["token", token]))
    cache_key = (auth_fp, addr, mount_point, path, namespace or "")

    if use_cache and CachedFetch is not None:
        cached = _CACHE.get(cache_key)
        if cached and cached.is_fresh(cache_ttl_seconds):
            return dict(cached.secrets), []
        if _DISK_CACHE is not None:
            disk_cached = _DISK_CACHE.read(cache_key, cache_ttl_seconds, home_path)
            if disk_cached is not None:
                _CACHE[cache_key] = disk_cached
                return dict(disk_cached.secrets), []

    secrets, warnings = _read_kv2(
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
    )

    if use_cache and CachedFetch is not None:
        entry = CachedFetch(secrets=secrets, fetched_at=time.time())
        _CACHE[cache_key] = entry
        if _DISK_CACHE is not None:
            _DISK_CACHE.write(cache_key, entry, cache_ttl_seconds, home_path)
    return secrets, warnings


# Valid env-var names that can nonetheless hijack how a process (or its
# subprocesses) resolves binaries, shared libraries, or interpreter startup.
# is_valid_env_name() accepts them, but a Vault payload must never be able to
# inject them, so they are dropped with a warning regardless of override
# settings. This keeps the plugin strictly stricter than a plain bulk source.
_DANGEROUS_ENV_NAMES = frozenset({
    "PATH", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "GLOBIGNORE",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONEXECUTABLE",
    "NODE_OPTIONS", "NODE_PATH",
})
_DANGEROUS_ENV_PREFIXES = ("LD_", "DYLD_", "BASH_FUNC_")


def _read_kv2(
    *,
    addr,
    path,
    mount_point,
    namespace,
    verify,
    timeout,
    auth_method,
    token,
    role_id,
    secret_id,
) -> Tuple[Dict[str, str], List[str]]:
    try:
        import hvac
        from hvac import exceptions as hvac_exceptions
    except ImportError as exc:
        raise RuntimeError(
            "hvac is not installed. Run `pip install hvac` in the Hermes "
            "environment to use the Vault secret source."
        ) from exc

    try:
        client = hvac.Client(
            url=addr, verify=verify, timeout=timeout, namespace=namespace,
        )
    except Exception as exc:  # defensive: never let client init escape
        raise RuntimeError(
            _transport_message(f"failed to create Vault client for {addr}", exc)
        ) from exc

    # -- authenticate ---------------------------------------------------
    try:
        if auth_method == "approle":
            client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        else:
            client.token = token
        authed = client.is_authenticated()
    except hvac_exceptions.Forbidden as exc:
        raise RuntimeError(f"Vault authentication forbidden: {exc}") from exc
    except hvac_exceptions.InvalidRequest as exc:
        raise RuntimeError(
            f"Vault authentication failed (invalid request): {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(_transport_message("Vault authentication", exc)) from exc
    if not authed:
        raise RuntimeError(
            "Vault authentication failed: credentials rejected "
            "(is_authenticated() returned False)."
        )

    # -- read the KV v2 path -------------------------------------------
    try:
        resp = client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=mount_point, raise_on_deleted_version=True,
        )
    except hvac_exceptions.InvalidPath as exc:
        raise RuntimeError(
            f"Vault path not found (invalidpath): {mount_point}/{path}: {exc}"
        ) from exc
    except hvac_exceptions.Forbidden as exc:
        raise RuntimeError(
            f"Vault read forbidden for {mount_point}/{path}: {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            _transport_message(f"Vault read for {mount_point}/{path}", exc)
        ) from exc

    data = None
    if isinstance(resp, dict):
        inner = resp.get("data")
        if isinstance(inner, dict):
            data = inner.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(
            "Vault returned an unexpected response shape (data.data missing)."
        )

    secrets: Dict[str, str] = {}
    warnings: List[str] = []
    for key, value in data.items():
        if not isinstance(key, str) or value is None:
            continue
        if not is_valid_env_name(key):
            warnings.append(f"Skipping secret {key!r}: not a valid env-var name")
            continue
        # Case-insensitive: on case-insensitive platforms (Windows) a key like
        # "Path" resolves to PATH, so match regardless of the payload's casing.
        upper_key = key.upper()
        if upper_key in _DANGEROUS_ENV_NAMES or upper_key.startswith(
            _DANGEROUS_ENV_PREFIXES
        ):
            warnings.append(
                f"Skipping secret {key!r}: refusing to inject a variable that "
                "could hijack process, library, or interpreter resolution"
            )
            continue
        # Only scalars map cleanly onto the string-typed process environment; a
        # structured value (list/dict) would stringify to an unusable repr, so
        # skip it with a warning instead.
        if isinstance(value, (str, int, float)):  # bool is a subclass of int
            secrets[key] = str(value)
        else:
            warnings.append(
                f"Skipping secret {key!r}: value type {type(value).__name__} is "
                "not a scalar (only strings and numbers become env vars)"
            )
    return secrets, warnings


def _transport_message(context: str, exc: Exception) -> str:
    """Build a RuntimeError message that ``_classify_vault_error`` can bucket."""
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if "timeout" in name or "timed out" in text:
        return f"{context} timed out: {exc}"
    if "connection" in name or "connection" in text or "refused" in text:
        return f"{context} connection error: {exc}"
    return f"{context} failed: {exc}"
