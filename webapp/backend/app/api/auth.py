from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta

from ..db.session import get_db
from ..models.user import User
from ..core.security import verify_password, create_access_token
from ..core.config import settings
from ..schemas.auth import Token, Registration
from ..core.security import get_password_hash

router = APIRouter()


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(body: Registration, db: Session = Depends(get_db)):
    username = body.username.strip()
    email = body.email.strip().lower()
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        raise HTTPException(status_code=409, detail="That username or email is already registered")
    user = User(username=username, email=email, hashed_password=get_password_hash(body.password), role="Asset Owner", is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(data={"sub": str(user.id)}, expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter((User.username == form_data.username) | (User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
