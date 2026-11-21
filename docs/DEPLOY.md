# NHTRS GitHub + VPS deployment guide

**Scope:** A single-server *fictional-data staging pilot*, not a certified nationwide production deployment. No NIN, passport or visa-verification service is connected.

## 1. GitHub and Codex

1. Create a **private** GitHub repository, for example `Newsoft4/nhtrs-platform`, and restrict collaborators. No repository was accessible to the build assistant at packaging time.
2. Upload the files in this folder to its `main` branch (keep `.env` local, never upload guest records). In a local terminal:

   ```bash
   git init -b main
   git add .
   git commit -m 'Prepare NHTRS privacy-scoped deployment pilot'
   git remote add origin git@github.com:Newsoft4/nhtrs-platform.git
   git push -u origin main
   ```

   Change the remote to your actual created private repo; the example URL above is not a verified existing repository.
3. In GitHub, run **Actions > NHTRS CI** to verify tests, syntax and container build. Review the CI workflow permissions and dependency versions before enabling it for external contributors.
4. Open the private repo in Codex. Its `AGENTS.md` gives the agent project-specific security constraints and follow-up engineering work. Codex cannot deploy safely without access to the configured repository and infrastructure.

## 2. Server prerequisites

- An Ubuntu/Linux VPS with Docker Engine and Compose plugin, SSH access for a restricted deployment user with permission to run Docker, and a domain name you control.
- DNS `A`/`AAAA` record for `NHTRS_DOMAIN` pointing at your VPS. Allow inbound TCP 80/443 and optionally UDP 443; restrict SSH, disable public database ports.
- Backups, encryption-at-rest for host/volumes, patching and monitoring. Treat Docker group access as root-equivalent.
- A deployment user with ownership of `/opt/nhtrs` (create once as administrator with `sudo mkdir -p /opt/nhtrs && sudo chown "$USER":"$USER" /opt/nhtrs`).
- Secure `.env` stored only at `/opt/nhtrs/.env` on the VPS, created with `python3 scripts/init_env.py` after installing Python `cryptography` (or generate it locally then transfer securely).
- Add `NHTRS_DOMAIN=nhtrs.newsoftplc.ng` to `.env`.

## 3. Initial staging installation

```bash
# On server (after source files are in /opt/nhtrs):
cd /opt/nhtrs
python3 -m venv .venv
.venv/bin/pip install cryptography
.venv/bin/python scripts/init_env.py       # prints initial password once; save securely
printf '\nNHTRS_DOMAIN=nhtrs.newsoftplc.ng\n' >> .env
chmod 600 .env
# Start single-node HTTPS deployment
docker compose -f compose.yaml -f compose.prod.yaml config -q
docker compose -f compose.yaml -f compose.prod.yaml up -d --build --wait
curl --fail --show-error https://nhtrs.newsoftplc.ng/api/health
```

`compose.prod.yaml` adds a Caddy HTTPS proxy with automatic certificate issuance/renewal. Certificates require correctly pointed DNS and reachable ports 80/443. The app keeps its internal HTTP port available only at `127.0.0.1:8000` on the host. The remote service has secure cookies and enforces its configured HTTPS origin.

## 4. Enable deployment from GitHub Actions

- GitHub repo **Settings > Environments > New environment > staging** and configure required reviewers, restrict deployment branches to `main`.
- Set *environment secrets* `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY` (private key of a dedicated deployment SSH identity), and `DEPLOY_KNOWN_HOSTS` (the **verified** pinned SSH host key; do not blindly accept an unverified ssh-keyscan output).
- Ensure `/opt/nhtrs/.env` already exists on VPS and is private. The workflow deliberately refuses to deploy without it.
- GitHub **Actions > Deploy NHTRS pilot to VPS > Run workflow**. An environment approval is required if configured.
- The deployment workflow transfers checked-out source, never `.env`, then validates Compose and starts both API and TLS proxy. Verify HTTPS, login, registration using **fictional data only**, checkout, WebSocket refresh and database persistence after restart.

## 5. Operational requirements before real guest data

Complete NDPA/Nigeria Data Protection Act DPIA, documented legal basis and regulatory mandates, privacy notices, limited retention and deletion, MFA/SSO, rate limiting, scoped administration, credential rotation, database migrations, Postgres backup/restore, image scanning, audit log immutability, application security penetration tests and an incident response plan. Do not connect NIMC/NIS or publish individual travel histories without separate authorisations and access controls.

## 6. Troubleshooting and rollback

```bash
cd /opt/nhtrs
docker compose -f compose.yaml -f compose.prod.yaml ps
docker compose -f compose.yaml -f compose.prod.yaml logs --tail=100 api caddy
```

For rollback, first preserve database/volumes and the currently deployed source revision, then redeploy a previously tested Git commit. **Do not** execute `docker compose down -v` on a server with data: that removes database volumes. `Base.metadata.create_all()` is only a bootstrap mechanism; add proper Alembic migrations before upgrading deployed schemas.
