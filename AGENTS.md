# Codex working instructions — NHTRS

NHTRS is a privacy-sensitive **fictional-data pilot** for reporting aggregate accommodation occupancy in Nigeria. Keep the national and state views aggregated. Do not add a central person search, guest movement history, covert tracking, broad law-enforcement guest-record access, or national identity/immigration lookups without lawful approval, a reviewed design and data-minimisation safeguards.

## Stack

Python FastAPI, SQLAlchemy, PostgreSQL (Docker), test SQLite, static HTML/CSS/JavaScript, property-scoped HMAC PMS webhook, encrypted private guest records, WebSocket occupancy change notifications. NIMC, NIS and Airbnb integrations are **not connected**.

## Development requirements

1. Work in a feature branch and use a pull request; never merge a deployment or security change without review.
2. Never commit `.env`, production credentials, customer identities or real NIN/passport/visa numbers; tests use only invented records.
3. Keep permissions explicit: national/state roles see aggregates, property users access their own records only. Maintain independent audit logs for guest-record access.
4. Ensure check-in/out and PMS replay receipt operations are transactional, test replay/race cases where feasible.
5. Validate input and add tests when changing APIs; retain TLS, secure cookies, CSRF, Argon2 password hashing and encryption.
6. Run `python -m pytest -q` and `python -m compileall -q app scripts`; run `node --check app/static/app.js` if Node is installed.
7. Update README and the OpenAPI export after route/schema changes. Before real-data deployment require an approved controller, DPIA, retention policy, MFA, backup/restore tests and independent security review.

## Example Codex tasks

- Add Alembic migrations without losing existing guest or audit data.
- Add MFA and administrator account deactivation, including WebSocket session revocation.
- Add metrics for reporting coverage and stale properties without disclosing individuals.
- Implement tenant-isolation and PMS webhook race-condition tests using PostgreSQL.
- Add backup/restore drills, retention/deletion jobs, managed secrets and log shipping.
