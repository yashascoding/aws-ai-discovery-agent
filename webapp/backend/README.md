# AI Registry Backend

## Setup
```bash
cd /home/yashas-bhagwat/aws-governance-poc/webapp/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit if needed
mkdir -p data
```

## Initialize admin
```bash
python scripts/init_admin.py
```

## Run
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Docs: http://127.0.0.1:8000/docs
