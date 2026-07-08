"""Contract conformance for VaultSource.

Runs the host's ``SecretSourceConformance`` kit against ``VaultSource``.
Requires the hermes-agent source tree on ``PYTHONPATH`` (for ``agent.*`` and
``tests.secret_sources.conformance``); hvac is NOT required, because the
unconfigured code paths short-circuit before any Vault call.

This suite lives in ``checks/`` rather than ``tests/`` on purpose: a local
``tests`` package would shadow the host ``tests`` package that carries the
conformance kit.
"""
import pytest

from hermes_vault_secret_source import VaultSource

from tests.secret_sources.conformance import SecretSourceConformance

_VAULT_ENV = (
    "VAULT_ADDR",
    "VAULT_TOKEN",
    "VAULT_ROLE_ID",
    "VAULT_SECRET_ID",
    "VAULT_NAMESPACE",
)


class TestVaultConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self, monkeypatch):
        # Hermetic: strip any ambient Vault env so the unconfigured-path checks
        # are deterministic on a dev box that happens to be running Vault.
        for var in _VAULT_ENV:
            monkeypatch.delenv(var, raising=False)
        return VaultSource()
