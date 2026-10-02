"""Behavioral tests for VaultSource.

hvac is mocked via ``sys.modules`` so these run with no network and no Vault
binary. Two layers are exercised:

* ``VaultSource.fetch`` config guards + error classification (backend stubbed);
* ``_client._read_kv2`` KV v2 parsing + env-name filtering (fake hvac client).
"""
import sys
import types

import pytest

from agent.secret_sources.base import ErrorKind

from hermes_vault_secret_source import VaultSource, _client


# --------------------------------------------------------------------------
# VaultSource.fetch - config guards (steps 1-6, no backend call reached)
# --------------------------------------------------------------------------

def test_missing_addr_is_not_configured(monkeypatch, tmp_path):
    for var in ("VAULT_ADDR", "VAULT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    result = VaultSource().fetch({"enabled": True, "path": "app/data"}, tmp_path)
    assert not result.ok
    assert result.error_kind is ErrorKind.NOT_CONFIGURED
    assert not result.secrets


def test_missing_path_is_not_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "root")
    result = VaultSource().fetch({"enabled": True}, tmp_path)
    assert result.error_kind is ErrorKind.NOT_CONFIGURED


def test_missing_token_is_not_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    result = VaultSource().fetch({"enabled": True, "path": "app/data"}, tmp_path)
    assert result.error_kind is ErrorKind.NOT_CONFIGURED


def test_missing_approle_creds_is_not_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)
    result = VaultSource().fetch(
        {"enabled": True, "path": "app/data", "auth_method": "approle"}, tmp_path
    )
    assert result.error_kind is ErrorKind.NOT_CONFIGURED


def test_unknown_auth_method_is_not_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    result = VaultSource().fetch(
        {"enabled": True, "path": "app/data", "auth_method": "ldap"}, tmp_path
    )
    assert result.error_kind is ErrorKind.NOT_CONFIGURED


# --------------------------------------------------------------------------
# VaultSource.fetch - bulk read + error mapping (backend stubbed)
# --------------------------------------------------------------------------

def test_bulk_read_injects_all_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "root")

    def fake_fetch(**kwargs):
        assert kwargs["path"] == "app/data"
        assert kwargs["auth_method"] == "token"
        assert kwargs["token"] == "root"
        return ({"API_KEY": "abc", "DB_URL": "postgres://x"}, ["a warning"])

    monkeypatch.setattr(_client, "fetch_vault_secrets", fake_fetch)
    result = VaultSource().fetch(
        {"enabled": True, "path": "app/data", "cache_ttl_seconds": 0}, tmp_path
    )
    assert result.ok
    assert result.secrets == {"API_KEY": "abc", "DB_URL": "postgres://x"}
    assert "a warning" in result.warnings


@pytest.mark.parametrize(
    "message, expected_kind",
    [
        ("Vault authentication forbidden: permission denied", ErrorKind.AUTH_FAILED),
        ("Vault path not found (invalidpath): secret/app", ErrorKind.REF_INVALID),
        ("Vault read timed out: deadline", ErrorKind.TIMEOUT),
        ("Vault authentication connection error: refused", ErrorKind.NETWORK),
        ("hvac is not installed. Run pip install hvac", ErrorKind.BINARY_MISSING),
        ("something entirely unexpected happened", ErrorKind.INTERNAL),
    ],
)
def test_backend_runtimeerror_is_classified(monkeypatch, tmp_path, message, expected_kind):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "root")

    def boom(**kwargs):
        raise RuntimeError(message)

    monkeypatch.setattr(_client, "fetch_vault_secrets", boom)
    result = VaultSource().fetch({"enabled": True, "path": "app/data"}, tmp_path)
    assert not result.ok
    assert result.error_kind is expected_kind
    assert not result.secrets


def test_fetch_never_raises_on_unexpected_backend_error(monkeypatch, tmp_path):
    # The backend contract is RuntimeError-only, but a corrupt shared cache
    # could surface e.g. ValueError. fetch() must still return a clean result
    # rather than let anything escape onto the startup path.
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "root")

    def boom(**kwargs):
        raise ValueError("corrupt cache file")

    monkeypatch.setattr(_client, "fetch_vault_secrets", boom)
    result = VaultSource().fetch({"enabled": True, "path": "app/data"}, tmp_path)
    assert not result.ok
    assert result.error_kind is ErrorKind.INTERNAL
    assert not result.secrets


# --------------------------------------------------------------------------
# VaultSource.fetch - ordered multi-path reads (paths:)
# --------------------------------------------------------------------------

def _stub_paths(monkeypatch, layers):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "root")
    calls = []

    def fake_fetch(**kwargs):
        calls.append(kwargs["path"])
        layer = layers[kwargs["path"]]
        if isinstance(layer, Exception):
            raise layer
        return dict(layer), [f"warn:{kwargs['path']}"]

    monkeypatch.setattr(_client, "fetch_vault_secrets", fake_fetch)
    return calls


def test_paths_merge_in_order_later_wins(monkeypatch, tmp_path):
    calls = _stub_paths(monkeypatch, {
        "shared": {"A": "shared-a", "B": "shared-b"},
        "machine": {"B": "machine-b", "C": "machine-c"},
    })
    result = VaultSource().fetch(
        {"enabled": True, "paths": ["shared", "machine"]}, tmp_path
    )
    assert result.ok
    assert calls == ["shared", "machine"]
    assert result.secrets == {"A": "shared-a", "B": "machine-b", "C": "machine-c"}
    assert result.warnings == ["warn:shared", "warn:machine"]


def test_paths_any_failed_layer_fails_whole_fetch(monkeypatch, tmp_path):
    # A partial merge would silently drop the missing layer's keys, so one
    # failed path must fail the fetch and contribute nothing.
    _stub_paths(monkeypatch, {
        "shared": {"A": "a"},
        "machine": RuntimeError("Vault path not found (invalidpath): secret/machine"),
    })
    result = VaultSource().fetch(
        {"enabled": True, "paths": ["shared", "machine"]}, tmp_path
    )
    assert not result.ok
    assert result.error_kind is ErrorKind.REF_INVALID
    assert not result.secrets


@pytest.mark.parametrize("cfg", [
    {"path": "one", "paths": ["two"]},
    {"paths": "not-a-list"},
    {"paths": ["ok", ""]},
    {"paths": ["ok", 3]},
])
def test_invalid_paths_config_is_not_configured(monkeypatch, tmp_path, cfg):
    calls = _stub_paths(monkeypatch, {})
    result = VaultSource().fetch({"enabled": True, **cfg}, tmp_path)
    assert result.error_kind is ErrorKind.NOT_CONFIGURED
    assert calls == []


def test_empty_paths_falls_back_to_path(monkeypatch, tmp_path):
    calls = _stub_paths(monkeypatch, {"one": {"A": "a"}})
    result = VaultSource().fetch(
        {"enabled": True, "path": "one", "paths": []}, tmp_path
    )
    assert result.ok and result.secrets == {"A": "a"}
    assert calls == ["one"]


# --------------------------------------------------------------------------
# _client._read_kv2 - KV v2 parsing against a fake hvac client
# --------------------------------------------------------------------------

def _install_fake_hvac(monkeypatch, *, data=None, authed=True,
                       raise_read=None, raise_login=None):
    # raise_read / raise_login, when set, are ``(exc_class_name, message)``.
    # The exception is built from THIS fake's own exceptions module so its class
    # identity matches what ``_read_kv2`` catches (a pre-built instance from a
    # different fake would slip past the ``except`` and misclassify).
    fake = types.ModuleType("hvac")
    exc_mod = types.ModuleType("hvac.exceptions")

    class VaultError(Exception):
        pass

    class Forbidden(VaultError):
        pass

    class InvalidPath(VaultError):
        pass

    class InvalidRequest(VaultError):
        pass

    exc_mod.VaultError = VaultError
    exc_mod.Forbidden = Forbidden
    exc_mod.InvalidPath = InvalidPath
    exc_mod.InvalidRequest = InvalidRequest

    class _KvV2:
        def read_secret_version(self, path, mount_point="secret",
                                raise_on_deleted_version=True):
            if raise_read is not None:
                name, msg = raise_read
                raise getattr(exc_mod, name)(msg)
            return {"data": {"data": dict(data or {})}}

    class _Client:
        def __init__(self, url=None, verify=True, timeout=30, namespace=None, **kw):
            self.token = None
            self.secrets = types.SimpleNamespace(
                kv=types.SimpleNamespace(v2=_KvV2())
            )
            self.auth = types.SimpleNamespace(
                approle=types.SimpleNamespace(login=self._login)
            )

        def _login(self, role_id=None, secret_id=None):
            if raise_login is not None:
                name, msg = raise_login
                raise getattr(exc_mod, name)(msg)

        def is_authenticated(self):
            return authed

    fake.Client = _Client
    fake.exceptions = exc_mod
    monkeypatch.setitem(sys.modules, "hvac", fake)
    monkeypatch.setitem(sys.modules, "hvac.exceptions", exc_mod)
    return fake


def _read(**over):
    kwargs = dict(
        addr="http://127.0.0.1:8200", path="app/data", mount_point="secret",
        namespace=None, verify=True, timeout=5.0, auth_method="token",
        token="root", role_id="", secret_id="",
    )
    kwargs.update(over)
    return _client._read_kv2(**kwargs)


def test_read_kv2_filters_and_coerces(monkeypatch):
    _install_fake_hvac(
        monkeypatch,
        data={"GOOD": "1", "bad-name": "2", "NUM": 5, "NULL": None},
    )
    secrets, warnings = _read()
    # bad-name skipped (invalid env name), NULL dropped (None), NUM coerced to str.
    assert secrets == {"GOOD": "1", "NUM": "5"}
    assert any("bad-name" in w for w in warnings)


def test_read_kv2_skips_process_hijacking_names(monkeypatch):
    _install_fake_hvac(
        monkeypatch,
        data={"GOOD": "1", "PATH": "/evil", "LD_PRELOAD": "x.so",
              "PYTHONPATH": "/p", "DYLD_INSERT_LIBRARIES": "y"},
    )
    secrets, warnings = _read()
    # Dangerous but valid-identifier names are refused even though injected here.
    assert secrets == {"GOOD": "1"}
    for name in ("PATH", "LD_PRELOAD", "PYTHONPATH", "DYLD_INSERT_LIBRARIES"):
        assert any(name in w for w in warnings)


def test_read_kv2_skips_non_scalar_values(monkeypatch):
    _install_fake_hvac(
        monkeypatch,
        data={"OK": "v", "NUM": 5, "FLAG": True, "OBJ": {"a": 1}, "LST": [1, 2]},
    )
    secrets, warnings = _read()
    # Scalars coerced (bool is a subclass of int -> "True"); structured skipped.
    assert secrets == {"OK": "v", "NUM": "5", "FLAG": "True"}
    assert any("OBJ" in w for w in warnings)
    assert any("LST" in w for w in warnings)


def test_read_kv2_auth_false_raises(monkeypatch):
    _install_fake_hvac(monkeypatch, data={}, authed=False)
    with pytest.raises(RuntimeError, match="credentials rejected"):
        _read()


def test_read_kv2_invalid_path_raises_classifiable(monkeypatch):
    _install_fake_hvac(monkeypatch, data={}, raise_read=("InvalidPath", "no secret here"))
    with pytest.raises(RuntimeError, match="invalidpath"):
        _read()


def test_read_kv2_approle_login_path(monkeypatch):
    _install_fake_hvac(monkeypatch, data={"TOKEN_A": "v"})
    secrets, _ = _read(auth_method="approle", token="", role_id="r", secret_id="s")
    assert secrets == {"TOKEN_A": "v"}


def test_read_kv2_missing_hvac_raises_binary_missing(monkeypatch):
    # Simulate hvac not installed: block the import.
    monkeypatch.setitem(sys.modules, "hvac", None)
    with pytest.raises(RuntimeError, match="not installed"):
        _read()


def test_read_kv2_denylist_is_case_insensitive(monkeypatch):
    # On case-insensitive platforms (Windows) "Path" resolves to PATH, so the
    # denylist must match regardless of the payload's casing.
    _install_fake_hvac(
        monkeypatch,
        data={"GOOD": "1", "Path": "/evil", "ld_preload": "x.so",
              "PyThOnPath": "/p", "Dyld_Insert_Libraries": "y"},
    )
    secrets, warnings = _read()
    assert secrets == {"GOOD": "1"}
    for name in ("Path", "ld_preload", "PyThOnPath", "Dyld_Insert_Libraries"):
        assert any(name in w for w in warnings)


# --------------------------------------------------------------------------
# _coerce_verify - TLS verify must fail closed, never silently open
# --------------------------------------------------------------------------

def test_coerce_verify_blank_string_fails_closed():
    from hermes_vault_secret_source import _coerce_verify

    # An empty or whitespace-only value is not a request to disable TLS; a
    # falsy return here would flip requests to CERT_NONE (MITM exposure).
    assert _coerce_verify("") is True
    assert _coerce_verify("   ") is True
    # Explicit disables and real CA-bundle paths still behave as documented.
    assert _coerce_verify("false") is False
    assert _coerce_verify("/etc/ssl/ca.pem") == "/etc/ssl/ca.pem"
    assert _coerce_verify(True) is True


def test_ttl_zero_disables_caching(monkeypatch, tmp_path):
    # cache_ttl_seconds: 0 must mean "no caching" at this layer too, so secret
    # values are never handed to the cache regardless of host ttl handling.
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "root")
    seen = {}

    def fake_fetch(**kwargs):
        seen.update(kwargs)
        return ({"K": "v"}, [])

    monkeypatch.setattr(_client, "fetch_vault_secrets", fake_fetch)
    VaultSource().fetch(
        {"enabled": True, "path": "app/data", "cache_ttl_seconds": 0}, tmp_path
    )
    assert seen["use_cache"] is False
    seen.clear()
    VaultSource().fetch(
        {"enabled": True, "path": "app/data", "cache_ttl_seconds": 300}, tmp_path
    )
    assert seen["use_cache"] is True


# --------------------------------------------------------------------------
# register() - the pip entry point Hermes calls to wire an external plugin
# --------------------------------------------------------------------------

def test_register_wires_vault_source():
    from hermes_vault_secret_source import register

    registered = []

    class _Ctx:
        def register_secret_source(self, source):
            registered.append(source)

    register(_Ctx())
    assert len(registered) == 1
    assert isinstance(registered[0], VaultSource)
