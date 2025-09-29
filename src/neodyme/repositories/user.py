from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from neodyme.models import User, UserCreate, UserUpdate

from .base import BaseRepository


class UserRepository(BaseRepository[User, UserCreate, UserUpdate]):
    async def get_by_email(self, session: AsyncSession, *, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        result = await session.exec(statement)
        return result.first()

    async def create(self, session: AsyncSession, *, obj_in: UserCreate) -> User:
        obj_data = obj_in.model_dump()
        hashed_password = self._hash_password(obj_data.pop("password"))
        obj_data["hashed_password"] = hashed_password

        db_obj = User(**obj_data)
        session.add(db_obj)
        await session.commit()
        await session.refresh(db_obj)
        return db_obj

    def _hash_password(self, password: str) -> str:
        import hashlib

        return hashlib.sha256(password.encode()).hexdigest()


user_repository = UserRepository(User)
