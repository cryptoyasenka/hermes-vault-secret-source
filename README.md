# hermes-vault-secret-source

A [HashiCorp Vault](https://developer.hashicorp.com/vault) secret source for
[Hermes Agent](https://github.com/NousResearch/hermes-agent), packaged as a
standalone pip plugin.

At Hermes startup it reads one Vault **KV v2** secret path and injects every
key found there as an environment variable, the same way the bundled Bitwarden
Secrets Manager source injects a whole project. This is a **bulk** source, so
explicit per-variable bindings from mapped sources (like 1Password) take
precedence over it.

## Install

```bash
pip install hermes-vault-secret-source
```

This pulls in [`hvac`](https://hvac.readthedocs.io/), the official Python client
for Vault. Install it into the same environment as `hermes-agent`.

Hermes discovers the plugin automatically through the `hermes_agent.plugins`
entry point, but plugins are opt-in. Enable it once:

```bash
hermes plugins enable hermes-hashicorp-vault
```

## Configure

Add a `vault` block under `secrets` in your Hermes config:

```yaml
secrets:
  vault:
    enabled: true
    # addr is read from $VAULT_ADDR by default; set `addr` to hard-code it.
    path: apps/my-agent          # KV v2 path whose keys become env vars
    mount_point: secret          # KV v2 mount (default: secret)
    auth_method: token           # "token" (default) or "approle"
    cache_ttl_seconds: 300       # 0 disables caching
```

Credentials are never written into config; they come from environment
variables:

| Auth method | Env vars used                                    |
|-------------|--------------------------------------------------|
| `token`     | `VAULT_ADDR`, `VAULT_TOKEN`                       |
| `approle`   | `VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID` |

The env-var names are overridable per field (`addr_env`, `token_env`,
`role_id_env`, `secret_id_env`) if your deployment uses different names.

### All config keys

| Key                       | Default        | Meaning                                         |
|---------------------------|----------------|-------------------------------------------------|
| `enabled`                 | `false`        | Master switch                                   |
| `addr`                    | `""`           | Vault URL; overrides `addr_env` when set        |
| `addr_env`                | `VAULT_ADDR`   | Env var holding the Vault URL                   |
| `path`                    | `""`           | KV v2 path to read (required)                   |
| `mount_point`             | `secret`       | KV v2 secrets-engine mount                      |
| `auth_method`             | `token`        | `token` or `approle`                            |
| `token_env`               | `VAULT_TOKEN`  | Env var with the token (token auth)             |
| `role_id_env`             | `VAULT_ROLE_ID`| Env var with the role_id (approle)              |
| `secret_id_env`           | `VAULT_SECRET_ID` | Env var with the secret_id (approle)         |
| `namespace`               | `""`           | Vault Enterprise namespace                      |
| `verify`                  | `true`         | TLS verify: `true`/`false` or a CA-bundle path  |
| `cache_ttl_seconds`       | `300`          | Disk+memory cache TTL; `0` disables caching     |
| `request_timeout_seconds` | `30`           | Per-request Vault HTTP timeout                  |
| `override_existing`       | `true`         | Vault values overwrite existing env values      |

## How it behaves

* **Never raises.** A misconfigured or unreachable Vault produces a clean
  `FetchResult` with an `ErrorKind` (`not_configured`, `auth_failed`,
  `ref_invalid`, `network`, `timeout`, ...), never a startup crash.
* **Protects its own credentials.** The auth env vars (`VAULT_ADDR`,
  `VAULT_TOKEN`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`) are marked protected, so a
  secret stored in Vault cannot clobber the credential used to reach Vault.
* **Caches values, never tokens.** The optional on-disk cache stores only the
  resolved secret values; the token/secret_id are SHA-256 fingerprinted before
  they touch the cache key.
* **Skips non-env-safe keys.** A KV key that is not a valid environment
  variable name is skipped with a warning rather than injected.

## Development

Requires a `hermes-agent` source checkout (for the `agent.*` packages and the
conformance kit at `tests/secret_sources/conformance.py`).

```bash
# host = hermes-agent checkout, plugin = this repo. Put the host on PYTHONPATH so
# `import tests` resolves to the host conformance package. This repo keeps its own
# tests in `checks/` (not `tests/`) precisely so it cannot shadow that package.
PYTHONPATH="/path/to/hermes-agent:$(pwd)" pytest
```

`checks/test_conformance.py` runs the host `SecretSourceConformance` contract;
`checks/test_vault_source.py` covers behavior with `hvac` mocked (no network, no
Vault binary needed).

To run against a real dev server:

```bash
vault server -dev            # prints VAULT_ADDR + a root token
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<root-token-from-output>
vault kv put secret/apps/my-agent API_KEY=abc DB_URL=postgres://x
```

## License

MIT
