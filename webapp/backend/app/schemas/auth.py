from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: int | None = None


class Registration(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=12, max_length=72)
