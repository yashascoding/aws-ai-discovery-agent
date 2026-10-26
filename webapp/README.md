# AI Registry Web Application

Built on top of the existing AWS AI Discovery Agent. Runs locally on Ubuntu.

## Architecture
- Frontend: React + TypeScript + Vite (http://localhost:5173)
- Backend: FastAPI (http://127.0.0.1:8000)
- Database: SQLite (local)
- Auth: JWT (simple, no Cognito)
- Discovery: Reuses existing `src/` discovery engine with real AWS account

## Quick Start

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
mkdir -p data
python scripts/init_admin.py  # create first admin
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend
```bash
cd frontend
pnpm install  # or npm install
pnpm dev
```

### AWS Configuration
Each signed-in user connects from **AWS connection** through AWS's browser
sign-in. The app verifies the returned identity and uses the AWS CLI's
temporary credentials for read-only discovery. It never asks users to paste
AWS passwords or access keys. Root, IAM user, and federated console sign-in are
supported by the AWS CLI flow; IAM users should have the read-only discovery
policy and `SignInLocalDevelopmentAccess` policy described in
`../docs/iam.md`.

Users can create an app login from the sign-in page. Each user's AWS sign-in
profile, scan history, and inventory are isolated from other app users.

## Usage
1. Start backend and frontend
2. Sign in with an Administrator account
3. Go to Dashboard → Start Discovery Scan (live AWS, read-only)
4. View Registry and open asset details
5. Edit governance metadata as Administrator or Asset Owner
6. Review audit history
7. Open **Coverage & Findings** to review per-service discovery/usage/billing
   status, reported cost, usage measurements, and open findings
8. Open an asset to see resource-linked evidence plus read-only service-level
   context (shared by all resources of that service, never attributed to one)
9. Run scan again: existing governance metadata is preserved and records are not duplicated

## New data model

Each completed scan stores four additional tables:

- `usage_measurements` — CloudWatch measurements, including `no_datapoints` and
  `partial` states.
- `cost_records` — Cost Explorer (or CUR) records with attribution confidence.
- `findings` — governance, telemetry, attribution, and cost-review findings.
- `service_capabilities` — per-scan coverage for the 55-service registry.

The dashboard reads the latest **completed** scan so a running scan cannot make
coverage or cost appear empty. Missing telemetry is shown as unavailable, never
as zero usage. Service-level cost is not allocated to resources without a billing
identifier.

## Tests

```bash
# Discovery engine (repository root)
pytest tests -q

# Webapp backend (from webapp/backend)
pytest tests -q
```
