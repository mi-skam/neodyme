from fastapi import APIRouter, Depends, status
from sqlmodel.ext.asyncio.session import AsyncSession

from neodyme.core import get_async_session
from neodyme.core.exceptions import ConflictError, NotFoundError
from neodyme.models import UserCreate, UserPublic, UserUpdate
from neodyme.repositories import user_repository

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    session: AsyncSession = Depends(get_async_session),
) -> UserPublic:
    existing_user = await user_repository.get_by_email(session, email=user_in.email)
    if existing_user:
        raise ConflictError("Email already registered")

    user = await user_repository.create(session, obj_in=user_in)
    return UserPublic.model_validate(user)


@router.get("/{user_id}", response_model=UserPublic)
async def get_user(
    user_id: int,
    session: AsyncSession = Depends(get_async_session),
) -> UserPublic:
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise NotFoundError("User not found")

    return UserPublic.model_validate(user)


@router.get("/", response_model=list[UserPublic])
async def get_users(
    skip: int = 0,
    limit: int = 100,
    session: AsyncSession = Depends(get_async_session),
) -> list[UserPublic]:
    users = await user_repository.get_multi(session, skip=skip, limit=limit)
    return [UserPublic.model_validate(user) for user in users]


@router.put("/{user_id}", response_model=UserPublic)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    session: AsyncSession = Depends(get_async_session),
) -> UserPublic:
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise NotFoundError("User not found")

    if user_in.email:
        existing_user = await user_repository.get_by_email(session, email=user_in.email)
        if existing_user and existing_user.id != user_id:
            raise ConflictError("Email already registered")

    update_data = user_in.model_dump(exclude_unset=True)
    if "password" in update_data:
        update_data["hashed_password"] = user_repository._hash_password(
            update_data.pop("password")
        )

    updated_user = await user_repository.update(
        session, db_obj=user, obj_in=update_data
    )
    return UserPublic.model_validate(updated_user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    session: AsyncSession = Depends(get_async_session),
) -> None:
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise NotFoundError("User not found")

    await user_repository.delete(session, id=user_id)
