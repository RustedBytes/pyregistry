# Company Adoption

Use this guide to evaluate Pyregistry inside a company. The goal is not only to
run a registry, but to create a package supply-chain workflow that teams can
understand and operate.

## Fit Checklist

Pyregistry is a good candidate when you need:

- Private Python package publishing.
- Tenant-scoped package namespaces.
- Standard Python client compatibility.
- Authenticated installs.
- PyPI-compatible mirroring.
- Admin visibility into packages, releases, tokens, and audit events.
- Provenance and trusted publishing foundations.
- Lightweight package security signals.
- A Rust codebase with clear Clean Architecture boundaries.

Consider another tool or more hardening if you need:

- A mature production PyPI clone today.
- Complex UI workflows.
- Organization-wide identity management already integrated.
- Advanced package retention policies out of the box.
- A fully managed SaaS registry.

## Pilot Plan

### Week 1: Local Evaluation

Goals:

- Build and run Pyregistry locally.
- Upload one internal demo package.
- Install it with `pip` and `uv`.
- Run `check-registry`, `validate-dist`, and `audit-wheel`.
- Read the architecture guide.

Success criteria:

- Developers can complete install and upload flows without custom tooling.
- The team understands where domain, application, web, and infrastructure code
  belongs.

### Week 2: Shared Internal Pilot

Goals:

- Deploy behind internal HTTPS.
- Use Postgres for metadata.
- Use S3-compatible object storage.
- Create one or two real tenants.
- Issue scoped read and publish tokens.
- Configure mirroring policy.
- Connect logs to company observability.

Success criteria:

- One team can publish from CI and install from another CI job.
- Backup and restore expectations are documented.
- Token ownership is clear.

### Week 3: Trust And Policy

Goals:

- Configure real OIDC issuer settings.
- Register trusted publishers for pilot packages.
- Decide whether direct public PyPI access is allowed.
- Define token rotation and expiration policy.
- Define vulnerability and wheel scan review policy.

Success criteria:

- CI can publish without a long-lived publish token.
- Security findings have an owner and response path.

## Tenant Design

Choose tenants around ownership and policy boundaries.

Good tenant examples:

- `platform`
- `data-science`
- `ml-infra`
- `payments`
- `staging`

Avoid creating a tenant for every package unless each package truly has
separate access control and operations.

## Policy Decisions

Before rollout, answer:

| Question | Why it matters |
| --- | --- |
| Who can create tenants? | Controls namespace growth and ownership. |
| Who can issue publish tokens? | Controls release authority. |
| Are tokens short-lived? | Reduces blast radius. |
| Is trusted publishing required? | Reduces long-lived CI secrets. |
| Is public PyPI reachable directly? | Affects dependency confusion and auditability. |
| Which upstream mirror is trusted? | Defines package source of truth. |
| What happens on vulnerability findings? | Makes scans actionable. |
| Who can purge artifacts? | Protects reproducibility and incident handling. |
| How long are audit events retained? | Supports compliance and investigations. |

## Recommended Company Defaults

For a first shared deployment:

- Use HTTPS only.
- Use Postgres metadata storage.
- Use S3-compatible artifact storage.
- Use one tenant per owning team or environment.
- Use read-only tokens for developers and build jobs.
- Use CI-only publish tokens or trusted publishing.
- Enable mirroring through the company-approved upstream.
- Keep direct public PyPI fallback out of default client templates.
- Review package scan results before broad internal promotion.
- Back up metadata and artifacts together.

## Operating Model

Define these roles:

| Role | Responsibility |
| --- | --- |
| Registry owner | Runs Pyregistry, manages deployment, backups, and upgrades. |
| Tenant owner | Manages tenant packages, tokens, publishers, and policies. |
| Package owner | Publishes releases and responds to package issues. |
| Security reviewer | Reviews vulnerability and wheel audit signals. |
| Platform engineer | Maintains CI templates and Python client configuration. |

## Contribution Model

When company teams extend Pyregistry:

- Keep domain logic independent of frameworks and databases.
- Put new business actions in application use cases.
- Define ports in the application layer.
- Implement adapters in infrastructure.
- Keep web handlers thin.
- Test domain rules and use cases before adapter details.
- Update these docs when the feature changes how teams operate.

## Rollout Risks

Track these before expansion:

- Token sprawl.
- Unclear tenant ownership.
- Direct public index fallback in CI.
- Missing backup restore test.
- Object storage and metadata drift.
- Long-running mirror refreshes.
- Reverse proxy request size limits.
- Logs containing secrets.
- Unreviewed trusted publisher claim rules.
- Security scan findings without owners.
