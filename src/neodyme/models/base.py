from datetime import datetime

from sqlmodel import Field, SQLModel


class TimestampMixin(SQLModel):
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"onupdate": datetime.utcnow},
    )


class BaseModel(TimestampMixin, table=True):
    __abstract__ = True

    id: int | None = Field(default=None, primary_key=True)


class BaseCreate(SQLModel):
    pass


class BaseUpdate(SQLModel):
    pass


class BaseInDB(TimestampMixin):
    id: int


class BasePublic(BaseInDB):
    pass
