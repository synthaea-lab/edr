# Synthaea Server - Development Setup

## Prerequisites

- Node.js 20+
- Docker and Docker Compose
- Git

## Quick Start

### 1. Install Dependencies

```bash
cd server
npm install
```

### 2. Setup Environment

```bash
cp .env.example .env
```

Edit `.env` if needed (defaults work for local development).

### 3. Generate Development Certificates

```bash
./scripts/generate-dev-certs.sh
```

This creates:
- `certs/ca.crt` - CA certificate
- `certs/server.crt/key` - Server certificate for nginx
- `certs/agent-test.crt/key` - Test agent client certificate

### 4. Start Development Stack

```bash
docker-compose up
```

This starts:
- **PostgreSQL** (port 5432)
- **Next.js server** (port 3000)
- **Nginx mTLS proxy** (port 8443)

The server creates its schema on startup with `prisma db push` (`prisma/migrations` is not
tracked, so there is no migration history to apply).

After editing `prisma/schema.prisma` in the dev stack, `db push` updates the database on the next
start but the Prisma client inside the container stays the one generated when the image was
built: rebuild the image (`docker compose build server`) to regenerate it.

The production image serves the standalone build with `node server.js`. Outside Docker,
`npm run build` then `npm start` does the same: `scripts/start-standalone.mjs` copies the static
assets and `public/` beside the standalone server (as the image does) and starts it, with `PORT`
and `HOSTNAME` read as usual. `next start` does not serve this output.

### Reaching the stack from an agent on another machine (a lab VM)

The dev certificate names `localhost`, `127.0.0.1` and `::1` only, and the agent's TLS client
(rustls) refuses a server name that is not in the certificate's `subjectAltName`. To reach the
proxy from a VM or another host, name its address when generating the certificates, and tell
the agent which CA to trust (it trusts the public roots only by default):

```bash
DEV_CERT_SANS="IP:192.0.2.10" ./scripts/generate-dev-certs.sh      # the address the agent will use
agent check-content-manifest --server https://192.0.2.10:8443 --ring canary_0 \
  --ca-cert certs/ca.crt --cert certs/agent-test.crt --key certs/agent-test.key
```

`--ca-cert`, `--cert` and `--key` are also on `agent run`, `apply-release` and
`apply-content-manifest`; `server.ca_cert` in `agent.toml` does the same for a configured agent
(`docs/operations/binary-releases.md`, "Control plane on a private CA"). The server identifies
an agent by the certificate's CN: an `agents` row whose `enrollment_id` is that CN must exist
(`agent-test-001` for the test certificate), or the routes answer `403 Agent not enrolled`.

**The compose file publishes PostgreSQL (`5432`, with the dev password) and the proxy (`8443`) on
every interface of the host.** On a shared network, publish only what the lab needs, with an
override file, and nothing for the database:

```yaml
# override.yml, used with: docker compose -f docker-compose.yml -f override.yml up
services:
  postgres:
    ports: !reset []
  proxy:
    ports: !override
      - "192.0.2.10:8443:8443"   # only the lab bridge address
```

On a host with SELinux enforcing (Fedora, RHEL) the compose bind mounts carry `:z`, which
relabels `server/` and `server/certs/` for the containers. The first build also downloads
the Node and nginx images, so it needs network access.

### 5. Verify

```bash
# Check health
curl http://localhost:3000/api/health

# Expected: {"status":"ok","timestamp":"..."}
```

### 6. Access Console

Open http://localhost:3000 in your browser.

## Development Workflow

### Running Tests

```bash
npm run test          # Unit tests
npm run test:e2e      # End-to-end tests
```

### Database Operations

```bash
# Generate Prisma client (after schema changes)
npm run db:generate

# Create migration
npm run db:migrate

# Push schema changes (dev only)
npm run db:push

# Open Prisma Studio
npm run db:studio
```

### Testing Agent Endpoints

#### Enroll Agent

```bash
curl -X POST http://localhost:3000/api/enrollment \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-test-001" \
  -H "Content-Type: application/json" \
  -d '{
    "enrollmentId": "agent-test-001",
    "hostname": "test-vm-01",
    "version": "0.1.0"
  }'
```

#### Upload Detection

```bash
curl -X POST http://localhost:3000/api/ingest/detection \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-test-001" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp_ns": 1726048800000000000,
    "technique": "T1059.001",
    "severity": "high",
    "event": {},
    "meta": {}
  }'
```

#### Send Heartbeat

```bash
curl -X POST http://localhost:3000/api/ingest/heartbeat \
  -H "X-Client-Cert-Verified: SUCCESS" \
  -H "X-Client-Cert-Subject: CN=agent-test-001"
```

#### Trigger Silent Agent Detection

```bash
curl http://localhost:3000/api/cron/detect-silent-agents \
  -H "Authorization: Bearer dev_cron_secret"
```

## Architecture

### Tech Stack

- **Next.js 14+** - App Router, React Server Components
- **PostgreSQL 15+** - Relational database with Row-Level Security
- **Prisma** - Type-safe ORM and migrations
- **better-auth** - Authentication with organization (tenant) support
- **Tailwind CSS** - Styling

### Directory Structure

```
server/
├── app/                    # Next.js App Router
│   ├── api/               # API routes
│   │   ├── ingest/       # Agent endpoints (mTLS)
│   │   ├── enrollment/   # Management API
│   │   ├── cases/        # Case queries
│   │   └── cron/         # Background jobs
│   ├── console/          # Analyst UI
│   └── login/            # Authentication
├── components/            # React components
├── lib/                   # Utilities
│   ├── prisma.ts         # Database client
│   ├── auth.ts           # Authentication
│   └── tenant.ts         # Tenancy helpers
├── prisma/               # Database schema and migrations
├── scripts/              # Utility scripts
├── docker-compose.yml    # Dev stack
├── Dockerfile            # Server container
└── nginx.conf            # mTLS proxy config
```

### Tenancy Model

- **Tenant** = Organization (better-auth)
- All data tables include `tenant_id`
- Row-Level Security enforces isolation
- Middleware injects tenant context from session

### Authentication Flow

1. User logs in → better-auth creates session
2. Middleware checks session → injects `x-tenant-id` header
3. API routes use `getTenantId()` → filters queries by tenant

### Agent Authentication (mTLS)

1. Agent connects via mTLS → nginx verifies client certificate
2. Nginx passes `X-Client-Cert-Subject` header to server
3. Server extracts enrollment ID from certificate CN
4. Finds agent record → gets tenant context

## Troubleshooting

### "Agent not enrolled" Error

- Agent must be enrolled first via `/api/enrollment`
- Certificate CN must match `enrollmentId`

### "No tenant context" Error

- User must be logged in
- User must be member of an organization

### PostgreSQL Connection Failed

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# View logs
docker-compose logs postgres
```

### Next.js Build Errors

```bash
# Clean build artifacts
rm -rf .next
npm run build
```

## Production Deployment

See `docs/deployment.md` for production setup instructions.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://synthaea:synthaea_dev@localhost:5432/synthaea` |
| `NEXTAUTH_URL` | Public URL of server | `http://localhost:3000` |
| `NEXTAUTH_SECRET` | Session encryption key | `dev_secret_change_in_production` |
| `BETTER_AUTH_SECRET` | Auth encryption key | `dev_secret_change_in_production` |
| `CRON_SECRET` | Cron job authorization | `dev_cron_secret` |
| `NOTIFY_SECRET_KEY` | `<keyId>:<64 hex>`, seals webhook signing secrets (AES-256-GCM). Unset: creating a notification channel answers 503 (ADR-0036) | unset |
| `NOTIFY_SECRET_KEY_PREVIOUS` | Older keys of the same form, comma-separated, used only to open what was sealed before a rotation; the delivery cron seals it again under the current key, a few channels a tick, after which the old key can be retired | unset |
| `NOTIFY_ALLOWED_PRIVATE_HOSTS` | `<tenant id>:<host>` entries, comma-separated: hosts that tenant's channel URL may resolve to a private address (an on-prem SOAR). No wildcard tenant; an entry without a tenant is ignored. Even an entry never opens loopback, link-local (the metadata address included), the unspecified address or a cloud metadata address (`fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`, `168.63.129.16`). An entry trusts a **name**, but DNS decides the address: a tenant who controls the DNS of an allowlisted name can point it at another internal address, and the error class shown in the console is a blind probe of what is reachable. Prefer IP literals, or names only the operator controls. The default resolver (c-ares) reads `resolv.conf`, not `/etc/hosts`. Set by whoever runs the server, never by a tenant | empty |
| `NOTIFY_CONSOLE_URL` | Public base URL of the console, used for the links in notification payloads (falls back to `NEXTAUTH_URL`; with neither, the links are null) | unset |
| `NOTIFY_ALLOWED_PORTS` | Ports besides 443 a channel URL may use | empty |
| `NODE_ENV` | Environment mode | `development` |
