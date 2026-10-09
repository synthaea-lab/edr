# Synthaea Server - Test Suite

Comprehensive test suite for Issue #28 acceptance criteria.

## Test Structure

```
tests/
├── unit/              # Unit tests (utilities, helpers)
├── integration/       # Integration tests (API endpoints, database)
├── e2e/              # End-to-end acceptance tests
├── helpers/          # Test utilities and fixtures
└── setup.ts          # Global test setup
```

## Running Tests

### Prerequisites

For integration tests, you need a test PostgreSQL database:

```bash
# Using Docker
docker run -d \
  --name synthaea-test-db \
  -e POSTGRES_DB=synthaea_test \
  -e POSTGRES_USER=synthaea \
  -e POSTGRES_PASSWORD=synthaea_test \
  -p 5433:5432 \
  postgres:15-alpine
```

### Unit Tests

Test utilities and helpers without database or server:

```bash
npm test tests/unit
```

### Integration Tests

Test API logic with database (requires test DB):

```bash
# Setup test database
npm run db:push -- --schema=prisma/schema.prisma

# Run integration tests
npm run test:integration
```

### E2E Acceptance Tests

Test full flow with running server (requires server + database):

```bash
# Start development stack
docker-compose up -d

# Wait for server to be ready
sleep 10

# Run acceptance tests
npm run test:e2e
```

Or manually:

```bash
cd tests/e2e
./run-acceptance-tests.sh
```

### All Tests

```bash
# Run unit + integration tests
npm test

# With UI
npm run test:ui
```

## Test Coverage

### Unit Tests

- ✅ `tests/unit/tenant.test.ts` - Certificate enrollment ID extraction

### Integration Tests

- ✅ `tests/integration/ingest.test.ts` - Detection upload, heartbeat, silence detection
- ✅ `tests/integration/api.test.ts` - Enrollment, case queries
- ✅ `tests/integration/tenancy.test.ts` - Multi-tenant isolation

### E2E Tests

- ✅ `tests/e2e/run-acceptance-tests.sh` - All three acceptance criteria

## Acceptance Criteria Coverage

### ✅ Criterion 1: Agent enrolls → uploads detection → appears in console

**Unit tests:**
- Detection payload validation
- Enrollment ID extraction from certificate

**Integration tests:**
- Agent enrollment flow
- Detection storage
- Tenant filtering

**E2E tests:**
- Full flow: enroll → upload → verify endpoint

### ✅ Criterion 2: Heartbeat-silence detection server-side

**Unit tests:**
- Timestamp comparison logic

**Integration tests:**
- Heartbeat updates last-seen
- Silent agent detection (>5 min)
- Case creation for silent agents
- Duplicate case prevention

**E2E tests:**
- Heartbeat endpoint
- Cron job execution

### ✅ Criterion 3: docker-compose up gives working dev stack

**E2E tests:**
- Server health check
- PostgreSQL connectivity
- Service status verification

## Test Helpers

### Database Helpers (`tests/helpers/db.ts`)

```typescript
import { cleanDatabase, createTestTenant, createTestAgent } from "./helpers/db";

// Clean database before each test
beforeEach(async () => {
  await cleanDatabase();
});

// Create test fixtures
const tenant = await createTestTenant();
const agent = await createTestAgent(tenant.id);
```

### HTTP Helpers (`tests/helpers/http.ts`)

```typescript
import { createMtlsHeaders, createDetectionPayload } from "./helpers/http";

// Create mTLS headers for agent requests
const headers = createMtlsHeaders("agent-test-001");

// Create detection payload
const payload = createDetectionPayload({
  technique: "T1059.001",
  severity: "critical",
});
```

## Writing New Tests

### Unit Test Example

```typescript
import { describe, it, expect } from "vitest";

describe("MyUtility", () => {
  it("should do something", () => {
    const result = myUtility("input");
    expect(result).toBe("expected");
  });
});
```

### Integration Test Example

```typescript
import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { cleanDatabase, createTestTenant, prisma } from "../helpers/db";

describe("MyAPI", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("should create resource", async () => {
    const tenant = await createTestTenant();

    const resource = await prisma.myModel.create({
      data: {
        tenantId: tenant.id,
        // ...
      },
    });

    expect(resource.id).toBeDefined();
  });
});
```

## Continuous Integration

In CI, tests run automatically:

1. Start test PostgreSQL database
2. Run Prisma migrations
3. Execute unit tests
4. Execute integration tests
5. Generate coverage report

E2E tests should run on pull request builds with full Docker stack.

## Troubleshooting

### "Database connection failed"

Ensure test database is running:

```bash
docker ps | grep synthaea-test-db
```

Create if missing:

```bash
docker run -d --name synthaea-test-db \
  -e POSTGRES_DB=synthaea_test \
  -e POSTGRES_USER=synthaea \
  -e POSTGRES_PASSWORD=synthaea_test \
  -p 5433:5432 \
  postgres:15-alpine
```

### "Server not responding" (E2E tests)

Start the development stack:

```bash
docker-compose up -d
```

Check health:

```bash
curl http://localhost:3000/api/health
```

### "Test timeout"

Increase timeout in vitest.config.ts:

```typescript
export default defineConfig({
  test: {
    testTimeout: 10000, // 10 seconds
  },
});
```

## Test Database Management

### Reset test database

```bash
# Drop all tables and recreate them from schema.prisma
# (prisma/migrations is not tracked, so there is no migration history to replay)
DATABASE_URL="postgresql://synthaea:synthaea_test@localhost:5433/synthaea_test" \
  npx prisma db push --force-reset --skip-generate
```

### Inspect test data

```bash
npx prisma studio
```

## Coverage Reports

Generate coverage:

```bash
npm test -- --coverage
```

View HTML report:

```bash
open coverage/index.html
```

## Best Practices

1. **Clean database before each test** - Use `beforeEach(cleanDatabase)`
2. **Disconnect after all tests** - Use `afterAll(prisma.$disconnect)`
3. **Use test helpers** - Don't repeat fixture creation
4. **Test tenant isolation** - Every test should verify multi-tenancy
5. **Mock external services** - Don't hit real APIs
6. **Test error cases** - Not just happy paths
7. **Keep tests fast** - Integration tests should run in < 5s each

## Next Steps

- [ ] Add component tests for React components
- [ ] Add API contract tests (OpenAPI validation)
- [ ] Add performance tests (load testing)
- [ ] Add security tests (SQL injection, XSS)
- [ ] Setup CI pipeline with test automation
