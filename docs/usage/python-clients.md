# Python Clients

Pyregistry speaks familiar Python packaging protocols so teams can use standard
tools. The tenant slug is part of the URL, and API tokens provide access.

## URLs

For tenant `acme` on a local server:

| Purpose | URL |
| --- | --- |
| Simple index | `http://127.0.0.1:3000/t/acme/simple/` |
| Project index | `http://127.0.0.1:3000/t/acme/simple/{project}/` |
| Legacy upload | `http://127.0.0.1:3000/t/acme/legacy/` |
| Artifact download | `http://127.0.0.1:3000/t/acme/files/{project}/{version}/{filename}` |
| Provenance | `http://127.0.0.1:3000/t/acme/provenance/{project}/{version}/{filename}` |

Use HTTPS in company environments.

## Token Scopes

| Scope | Use |
| --- | --- |
| `read` | Install packages and download artifacts. |
| `publish` | Upload packages with `twine` or a trusted publishing token. |
| `admin` | Tenant administration workflows. |

Issue narrow tokens where possible. For CI, prefer separate read and publish
tokens unless one job truly needs both.

## Install With pip

```bash
export PYREGISTRY_TOKEN="pyr_..."

python -m pip install \
  --index-url "https://__token__:${PYREGISTRY_TOKEN}@registry.example.com/t/acme/simple/" \
  your-package
```

Use `--extra-index-url` only when you intentionally want fallback behavior.
For internal packages, `--index-url` is usually safer because it avoids
unexpected resolution from a public index.

## Install With uv

```bash
export PYREGISTRY_TOKEN="pyr_..."

uv pip install \
  --index-url "https://__token__:${PYREGISTRY_TOKEN}@registry.example.com/t/acme/simple/" \
  your-package
```

For company templates, place the index URL in your project or CI configuration
and inject the token from the secret manager.

## Upload With twine

Build your Python distribution first:

```bash
python -m build
```

Upload:

```bash
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="pyr_..."

twine upload \
  --repository-url "https://registry.example.com/t/acme/legacy/" \
  dist/*
```

The upload path accepts Python package metadata and stores wheels or source
distributions as registry artifacts.

## pip Configuration Example

For a developer machine:

```ini
[global]
index-url = https://__token__:pyr_REPLACE_ME@registry.example.com/t/acme/simple/
```

For shared documentation, do not commit real tokens. Prefer a placeholder and
teach developers to inject a token from their password manager or company
secret tooling.

## Trusted Publishing Shape

Trusted publishing is intended for CI systems:

1. Platform CI obtains an OIDC identity token.
2. CI calls `POST /_/oidc/mint-token`.
3. Pyregistry verifies the issuer and claim rules.
4. CI receives a short-lived publish token.
5. CI uploads to `/t/{tenant}/legacy/` with `twine`.

The local template includes a development JWKS issuer. Company environments
should configure real issuer, JWKS, and audience values and register trusted
publishers per tenant and project.

## Recommended Company Defaults

Use these defaults for a first pilot:

| Area | Recommendation |
| --- | --- |
| Read installs | Use tenant read tokens scoped to teams or environments. |
| Publishing | Use CI-only publish tokens or trusted publishing. |
| Public fallback | Prefer mirroring through Pyregistry instead of direct `extra-index-url` to PyPI. |
| Secrets | Store tokens in CI or company secret managers. |
| Naming | Create tenants around ownership boundaries, not every individual project. |
