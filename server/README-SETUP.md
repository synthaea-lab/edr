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
| `NODE_ENV` | Environment mode | `development` |
