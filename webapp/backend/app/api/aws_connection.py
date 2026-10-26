"""Browser-based AWS sign-in for each application user.

AWS CLI stores short-lived console credentials in the user's local AWS config
directory. The app never receives or persists an AWS password or access key.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from queue import Empty, Queue
from threading import Lock, Thread

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.config import settings
from ..db.session import get_db
from ..deps.auth import get_current_user
from ..models.user import User
from src.aws_identity import get_identity
from src.config import ScanConfig

router = APIRouter()
_processes: dict[int, subprocess.Popen] = {}
_output: dict[int, Queue[str | None]] = {}
_process_lock = Lock()


class SignInCode(BaseModel):
    code: str = Field(min_length=1, max_length=4096)


def _profile_for(user: User) -> str:
    return f"ai-registry-user-{user.id}"


def _read_lines(process: subprocess.Popen, output: Queue[str | None]) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        output.put(line)
    output.put(None)


@router.get("")
def get_connection(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    identity = None
    if user.aws_profile:
        identity = get_identity(ScanConfig(profile=user.aws_profile, regions=[settings.AWS_DEFAULT_REGION]))
    return {
        "connected": bool(identity and identity.success),
        "profile": user.aws_profile,
        "account_id": identity.account_id if identity and identity.success else None,
        "caller_arn": identity.caller_arn if identity and identity.success else None,
        "error": identity.error if identity and not identity.success else None,
    }


@router.post("/login/start")
def start_aws_login(user: User = Depends(get_current_user)):
    if not shutil.which("aws"):
        raise HTTPException(status_code=503, detail="AWS CLI is unavailable in the app. Rebuild the Compose image and try again.")

    profile = _profile_for(user)
    with _process_lock:
        prior = _processes.pop(user.id, None)
        _output.pop(user.id, None)
        if prior and prior.poll() is None:
            prior.terminate()
        try:
            process = subprocess.Popen(
                ["aws", "login", "--remote", "--profile", profile, "--region", settings.AWS_DEFAULT_REGION],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env={**os.environ, "AWS_PAGER": "", "HOME": os.environ.get("HOME", "/home/app")},
            )
        except OSError as exc:
            raise HTTPException(status_code=503, detail=f"Could not start AWS sign-in: {exc}") from exc

        output: Queue[str | None] = Queue()
        _processes[user.id] = process
        _output[user.id] = output
        Thread(target=_read_lines, args=(process, output), daemon=True).start()

    transcript = ""
    for _ in range(30):
        try:
            line = output.get(timeout=1)
        except Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        transcript += line
        match = re.search(r"https://[^\s\"'<>]+", transcript)
        if match:
            return {"profile": profile, "authorization_url": match.group(0).rstrip(".,)")}
        if process.poll() is not None:
            break

    with _process_lock:
        _processes.pop(user.id, None)
        _output.pop(user.id, None)
    if process.poll() is None:
        process.terminate()
    raise HTTPException(
        status_code=502,
        detail="AWS sign-in did not provide a browser link. Check the AWS CLI version and app logs, then retry.",
    )


@router.post("/login/complete")
def complete_aws_login(
    body: SignInCode,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    code = body.code.strip()
    if "\n" in code or "\r" in code:
        raise HTTPException(status_code=422, detail="Enter the single-use code shown by AWS.")
    with _process_lock:
        process = _processes.get(user.id)
    if not process or process.poll() is not None or process.stdin is None:
        raise HTTPException(status_code=400, detail="AWS sign-in expired. Start the sign-in again.")

    try:
        process.stdin.write(code + "\n")
        process.stdin.flush()
        process.wait(timeout=120)
    except subprocess.TimeoutExpired:
        process.terminate()
        raise HTTPException(status_code=408, detail="AWS sign-in timed out. Start again and finish the browser step.")
    finally:
        with _process_lock:
            _processes.pop(user.id, None)
            _output.pop(user.id, None)

    if process.returncode != 0:
        raise HTTPException(status_code=400, detail="AWS did not accept that sign-in code. Start again and use the latest code.")

    profile = _profile_for(user)
    identity = get_identity(ScanConfig(profile=profile, regions=[settings.AWS_DEFAULT_REGION]))
    if not identity.success:
        raise HTTPException(status_code=400, detail=f"AWS sign-in finished, but identity verification failed: {identity.error or 'unknown error'}")

    user.aws_profile = profile
    db.add(user)
    db.commit()
    return {
        "connected": True,
        "account_id": identity.account_id,
        "caller_arn": identity.caller_arn,
        "profile": profile,
        "region": identity.region,
    }
