from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .db.session import engine, Base
from .api import auth, assets, discovery, dashboard, aws_connection
from sqlalchemy import inspect, text

# Create tables
Base.metadata.create_all(bind=engine)

# Small additive migration for existing local POC databases.
with engine.begin() as connection:
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "aws_role_arn" not in user_columns:
        connection.execute(text("ALTER TABLE users ADD COLUMN aws_role_arn VARCHAR"))
    if "aws_external_id" not in user_columns:
        connection.execute(text("ALTER TABLE users ADD COLUMN aws_external_id VARCHAR"))
    if "aws_profile" not in user_columns:
        connection.execute(text("ALTER TABLE users ADD COLUMN aws_profile VARCHAR"))
    scan_columns = {column["name"] for column in inspect(engine).get_columns("scan_runs")}
    if "owner_user_id" not in scan_columns:
        connection.execute(text("ALTER TABLE scan_runs ADD COLUMN owner_user_id INTEGER"))
    # Preserve existing local scan history under the first administrator.
    connection.execute(text(
        "UPDATE scan_runs SET owner_user_id = (SELECT id FROM users WHERE role = 'Administrator' ORDER BY id LIMIT 1) "
        "WHERE owner_user_id IS NULL AND EXISTS (SELECT 1 FROM users WHERE role = 'Administrator')"
    ))
    connection.execute(text(
        "UPDATE scan_runs SET account_id = json_extract(metadata_json, '$.account_id') "
        "WHERE account_id IS NULL AND json_valid(metadata_json)"
    ))

app = FastAPI(title="AI Registry", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(discovery.router, prefix="/api/discovery", tags=["discovery"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(aws_connection.router, prefix="/api/aws-connection", tags=["aws-connection"])


@app.get("/api/health")
def health():
    return {"status": "ok"}
