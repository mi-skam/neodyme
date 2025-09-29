from datetime import datetime

from sqlmodel import Field, SQLModel

from .base import BaseCreate, BaseInDB, BaseModel, BasePublic, BaseUpdate


class UserBase(SQLModel):
    email: str = Field(unique=True, index=True, max_length=255)
    full_name: str = Field(max_length=255)
    is_active: bool = Field(default=True)


class User(UserBase, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"onupdate": datetime.utcnow},
    )


class UserCreate(UserBase, BaseCreate):
    password: str = Field(min_length=8, max_length=100)


class UserUpdate(BaseUpdate):
    email: str | None = Field(default=None, max_length=255)
    full_name: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=8, max_length=100)
    is_active: bool | None = None


class UserInDB(UserBase, BaseInDB):
    hashed_password: str


class UserPublic(UserBase, BasePublic):
    pass
