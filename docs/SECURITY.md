# Security and compliance notes (snow-utils-pat)

This document summarizes **security principles implemented in this repository**, **residual risks**, and a **high-level assessment** for security reviewers. It is not a formal certification, penetration-test report, or legal attestation.

## Assessment summary (informal)

| Area | Notes |
|------|--------|
| **Secret handling (PAT)** | Strong default: PAT material is stored in the **OS keychain** via Python `keyring`, not written to `.env` or project files. JSON success output **redacts** the PAT (`***REDACTED***`). |
| **Snowflake object model** | PATs are scoped with **role restriction**, **authentication policy** (PAT-only path), and **network policy** aligned with Snowflake guidance. |
| **Operational safety** | `remove` uses **per-step confirmation** (skippable with `--yes`); `show-pat` and `--print` are **explicitly dangerous** and labeled. |
| **Supply chain / SDLC** | Standard Python packaging; **no embedded secrets** in repo; `.env` is **gitignored**. Formal SBOM, signed releases, and org-wide policies are **out of scope** for this doc. |

**Informal rating (security posture of the tool as designed): 8/10** for a small CLI that manages long-lived Snowflake credentials—**provided** operators follow Snowflake least-privilege practices, avoid `show-pat`/`--print` in CI logs, and treat `snow` CLI + connection profiles as part of their trust boundary.

**Why not higher:** debug modes can increase logging; outbound calls for IP/CIDR presets add third-party dependency; the Python connector still holds the PAT in process memory for the short verification session; compliance frameworks (SOC2, FedRAMP, etc.) require **your** controls around accounts, roles, logging, and change management, not just this tool.

---

## Security principles followed in this project

### 1. Secrets minimization and storage

- **PAT is not persisted in repo files.** The tool does not commit or require PATs in source control.
- **PAT is not written to `.env` for normal auth.** Legacy `SA_PAT`-style lines are **stripped** when `.env` is rewritten; see [`pat.py`](../src/snow_utils_pat/pat.py) (`_strip_obsolete_dotenv_pat_lines`, `clear_env`).
- **OS keyring is the primary secret store** for PAT material, with a **deterministic service string** derived from host, account, user, and PAT name ([`_keyring_store.py`](../src/snow_utils_pat/_keyring_store.py)). This matches the intent of connector-style credential separation.

### 2. Safe-by-default CLI output

- **`create` / `rotate` JSON output** includes `pat: "***REDACTED***"` rather than the raw token ([`pat.py`](../src/snow_utils_pat/pat.py)).
- **`--print` cannot be combined with `-o json`** to avoid structured logs accidentally capturing the secret.
- **Dry-run** can print SQL; PAT generation SQL does not embed the secret (token comes from Snowflake’s response at execution time).

### 3. Dangerous operations are explicit and gated

- **`show-pat`** prints the raw PAT to stdout only after an **interactive warning** (unless `--yes`), with stderr warnings about history and logs ([`pat.py`](../src/snow_utils_pat/pat.py)).
- **`--print`** on `create`/`rotate` is documented as insecure and prints to stdout with a warning.
- **`remove`** requires **`--yes` in non-interactive environments** to avoid accidental scripted destruction without acknowledgment.

### 4. Snowflake security controls (design intent)

- **Service user** + **dedicated role** for PAT **role restriction** (least privilege is configured by the operator when choosing the role’s grants).
- **Authentication policy** restricts the user to **programmatic access token** usage with **network policy evaluation** enforced for PATs ([`get_auth_policy_sql`](../src/snow_utils_pat/pat.py)).
- **Network policy** with **ingress** rules; optional **`--allow-gh`** uses a **hybrid** policy referencing **Snowflake-managed** `SNOWFLAKE.NETWORK_SECURITY` rules where applicable ([`_network_helpers.py`](../src/snow_utils_pat/_network_helpers.py), [`_presets.py`](../src/snow_utils_pat/_presets.py)).
- **`remove` does not drop** Snowflake-managed rules under `SNOWFLAKE.NETWORK_SECURITY`; it drops **your** account policy and **`{db}.NETWORKS.{user}`** rule only ([`cleanup_network_for_user`](../src/snow_utils_pat/_network_helpers.py)).

### 5. Process and subprocess boundaries

- SQL and connection operations are delegated to the **`snow` CLI** via `subprocess` with argument lists (no shell interpolation in those wrappers) ([`_snow.py`](../src/snow_utils_pat/_snow.py)).
- **Verification** uses **`snowflake-connector-python`** with **`authenticator='PROGRAMMATIC_ACCESS_TOKEN'`** and the PAT as **`token`** ([`_verify_pat_connector`](../src/snow_utils_pat/_verify_pat_connector.py), [`verify_connection`](../src/snow_utils_pat/pat.py)). The PAT is **not** passed to a `snow` subprocess via **`SNOWFLAKE_PASSWORD`**. Same-user process visibility and host security policies still apply to the Python process.

### 6. Optional masking for CLI tooling

- Snow output masking helpers exist for **non-PAT** sensitive patterns (e.g. IPs, AWS account IDs) when enabled ([`_snow.py`](../src/snow_utils_pat/_snow.py)). PAT masking is handled by **not emitting** the PAT in JSON success paths.

### 7. Configuration hygiene

- **`.env` is gitignored** ([`.gitignore`](../.gitignore)); operators should keep secrets out of tracked files.
- **`load_dotenv()`** loads environment for convenience; **do not place PATs in `.env`** for use with this tool’s normal `verify` / `create` keyring flow.

---

## Residual risks and reviewer checklist

1. **Verification process memory**: the connector holds the PAT for the duration of the check; protect hosts from untrusted same-user memory inspection and avoid `--debug` in shared logs if output might leak connection details.
2. **`show-pat` / `--print`**: treat as **break-glass** only; disable in CI or wrap with secret-scanning awareness.
3. **Admin role** (`--admin-role`, default `ACCOUNTADMIN`): tighten in production to a custom role with **minimal** privileges for the DDL this tool runs.
4. **Outbound HTTP** for presets (`ipify`, Google IP ranges, etc.): network egress policy, TLS trust store, and vendor availability are **organizational** concerns.
5. **`--allow-gh` / managed rules**: not available in **government** regions per Snowflake; wrong rule FQN causes SQL failure—validate with `SHOW NETWORK RULES IN SNOWFLAKE.NETWORK_SECURITY`.
6. **Snowflake CLI profiles and tokens** on disk: this tool assumes **`snow`** authentication is configured securely outside this repo.

---

## Compliance mapping (high level, non-exhaustive)

| Theme | How this tool contributes |
|--------|---------------------------|
| **Least privilege** | PAT role restriction + operator-chosen grants; avoid over-broad admin role where possible. |
| **Separation of duties** | Separate human admin session (`snow`) from automated PAT user; use disposable service users for automation. |
| **Auditability** | Snowflake **access history** / query history capture `snow`-driven DDL and PAT user activity; this CLI does not replace account logging. |
| **Data protection** | PAT not written to project `.env` by design; keyring storage reduces accidental file leakage. |

For authoritative Snowflake behavior (PATs, policies, network rules), use **[Snowflake Documentation](https://docs.snowflake.com/)** (e.g. [Programmatic access tokens](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens), [Network policies](https://docs.snowflake.com/en/user-guide/network-policies.html)).

---

## Related documentation

- [README.md](../README.md) — quick start, keyring layout, `verify` / `show-pat` warnings.
- [docs/it/README.md](it/README.md) — integration testing and smoke script (non-production accounts).
