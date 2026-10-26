from sqlalchemy.orm import Session

from ..models.scan import ScanRun

COMPLETED_STATUSES = ("succeeded", "partially succeeded")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def latest_completed_scan(db: Session, owner_user_id: int | None = None) -> ScanRun | None:
    query = db.query(ScanRun).filter(ScanRun.status.in_(COMPLETED_STATUSES))
    if owner_user_id is not None:
        query = query.filter(ScanRun.owner_user_id == owner_user_id)
    return (
        query
        .order_by(ScanRun.created_at.desc(), ScanRun.id.desc())
        .first()
    )


def latest_completed_scan_id(db: Session, owner_user_id: int | None = None) -> str | None:
    scan = latest_completed_scan(db, owner_user_id)
    return scan.scan_id if scan else None


def owned_account_ids(db: Session, owner_user_id: int) -> list[str]:
    return [account_id for (account_id,) in db.query(ScanRun.account_id).filter(
        ScanRun.owner_user_id == owner_user_id, ScanRun.account_id.isnot(None)
    ).distinct().all()]
