# Contributing to Taimen IAM Service

Thank you for taking the time to contribute. Taimen is an organizational
runtime in which people, AI agents, workflows and services execute the work
of an organization; the platform is developed in the open under the
Apache License 2.0. This repository holds the **IAM Service** — the
product-neutral identity and access service of the platform (tenants and
principals, identity federation, SCIM provisioning, Platform Access Tokens
and audience-bound token exchange) — together with `iam_client`, the
reference client for local harnesses.

## Before you start

- Read the [Product Vision](https://github.com/monthu56/taimen/blob/main/docs/product-vision.md)
  and the [ADR registry](https://github.com/monthu56/taimen/blob/main/docs/adr/README.md).
  Architecture decisions are recorded as ADRs (in Russian, with an English
  title line); English summaries are provided on request in the ADR's
  discussion. This component has no ADR series of its own: its boundaries
  are set by the umbrella ADRs (ADR-0013 separates IAM from entitlement and
  domain authorization), so a change to the identity model, the token
  contract or the service boundary starts with an umbrella ADR.
- Check the [roadmap](https://github.com/monthu56/taimen/blob/main/docs/roadmap.md)
  and open issues before starting a large change. For anything that changes
  an API, a data model or a service boundary, open an issue first and
  propose an ADR.

## Contributor License Agreement

We require a signed Contributor License Agreement (CLA) for every
contribution, so that the project can be relicensed or defended without
tracking down every author. The CLA is checked by cla-assistant on each pull
request; you sign once.

- Individuals: [`cla/CLA-individual.md`](https://github.com/monthu56/taimen/blob/main/cla/CLA-individual.md)
- Companies contributing on behalf of employees: [`cla/CLA-entity.md`](https://github.com/monthu56/taimen/blob/main/cla/CLA-entity.md)

The CLA grants the project a copyright and patent licence to your
contribution; you keep your copyright.

## Development setup

The service is a standalone [uv](https://docs.astral.sh/uv/) project on
Python 3.12 (`.python-version`). It has no path dependencies on sibling
repositories, so it can be developed from its own checkout as well as from
the umbrella (`git clone --recurse-submodules <umbrella-url>`, then
`make check-iam-service`).

```bash
uv sync                       # runtime dependencies plus the `dev` group (pytest, ruff, aiosqlite)
uv run pytest                 # unit tests; no services needed
uv run ruff check .           # lint
uv run ruff format --check .  # formatting, checked in CI as well
```

The test suite is self-contained: the database is SQLite through `aiosqlite`,
the migration round-trip test runs against a temporary SQLite file, and
upstream identity providers are replaced by the in-process fake OIDC issuer
from `tests/conftest.py`. This is exactly what CI runs.

To run the service itself you need PostgreSQL and an RS256 signing key that
stays out of Git (`.secrets/` is ignored):

```bash
mkdir -p .secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out .secrets/iam-signing.pem
docker compose up --build     # PostgreSQL on localhost:5435, API on http://localhost:8010
```

The schema is changed by Alembic only (`IAM_CREATE_SCHEMA_ON_STARTUP` stays
`false`). Against the Compose database:

```bash
IAM_DATABASE_URL=postgresql+psycopg://iam:iam@localhost:5435/iam uv run alembic upgrade head
```

A schema change comes with a migration in `migrations/versions/` named like
the existing ones (`NNNN_<slug>`, explicit `revision` / `down_revision`) that
upgrades and downgrades cleanly; `tests/test_migrations.py` checks the
round-trip.

Integration tests against a live Keycloak with LDAP federation are marked
`integration` and skipped unless the `IAM_TEST_*` variables are set. The
reference deployment and the variables are described in
[`deploy/keycloak/README.md`](deploy/keycloak/README.md); then run
`uv run pytest -m integration`.

## Pull requests

- One logical change per pull request; keep the history linear (rebase, no
  merge commits).
- Tests and `ruff check` / `ruff format --check` must pass; behaviour changes
  come with tests.
- Commit messages explain *why*, not *what*; reference the ADR or issue.
- Public API changes (routes, schemas, token claims, `iam auth` CLI, env
  variables) update the README, which documents the HTTP and token
  contracts, and, when they break compatibility, the umbrella's
  `docs/migration-vX.Y.md`.
- The pull request template asks you to confirm the CLA and that no secrets,
  customer data or internal hostnames are included.

## Reporting bugs and security issues

Bugs: open an issue in this repository with the version, steps to reproduce
and logs. Security issues: see [SECURITY.md](SECURITY.md) and do not open a
public issue.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
