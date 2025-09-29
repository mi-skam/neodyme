import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from neodyme.core.database import create_db_and_tables, get_async_session_context
from neodyme.models import User, UserCreate
from neodyme.repositories import user_repository


class TestDatabaseUtilities:
    """Test database utility functions."""

    @pytest.mark.asyncio
    async def test_create_db_and_tables(self) -> None:
        """Test creating database tables."""
        # Create a test engine with in-memory SQLite
        test_engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
        )

        # Override the global engine temporarily
        import neodyme.core.database as db_module
        original_engine = db_module.engine
        db_module.engine = test_engine

        try:
            # Test the function
            await create_db_and_tables()

            # Verify tables were created by checking if we can insert data
            async with test_engine.begin() as conn:
                # Check that users table exists by trying to query it
                result = await conn.execute(
                    SQLModel.metadata.tables['users'].select().limit(0)
                )
                assert result is not None

        finally:
            # Restore original engine
            db_module.engine = original_engine
            await test_engine.dispose()

    @pytest.mark.asyncio
    async def test_get_async_session_context_success(self) -> None:
        """Test successful session context manager."""
        # Create a test engine with in-memory SQLite
        test_engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
        )

        # Create tables
        async with test_engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        # Override the global session maker temporarily
        import neodyme.core.database as db_module
        from sqlalchemy.ext.asyncio import async_sessionmaker

        original_session_maker = db_module.async_session_maker
        test_session_maker = async_sessionmaker(
            test_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        db_module.async_session_maker = test_session_maker

        try:
            # Test successful context
            async with get_async_session_context() as session:
                # Create a user to test the session works
                user_create = UserCreate(
                    email="context@example.com",
                    full_name="Context Test User",
                    password="testpassword123",
                )
                user = await user_repository.create(session, obj_in=user_create)
                assert user.id is not None

            # Verify the transaction was committed by querying in a new session
            async with test_session_maker() as verify_session:
                found_user = await user_repository.get_by_email(
                    verify_session, email="context@example.com"
                )
                assert found_user is not None
                assert found_user.email == "context@example.com"

        finally:
            # Restore original session maker
            db_module.async_session_maker = original_session_maker
            await test_engine.dispose()

    @pytest.mark.asyncio
    async def test_get_async_session_context_rollback_on_error(self) -> None:
        """Test session context manager rollback on error."""
        # Create a test engine with in-memory SQLite
        test_engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
        )

        # Create tables
        async with test_engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        # Override the global session maker temporarily
        import neodyme.core.database as db_module
        from sqlalchemy.ext.asyncio import async_sessionmaker

        original_session_maker = db_module.async_session_maker
        test_session_maker = async_sessionmaker(
            test_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        db_module.async_session_maker = test_session_maker

        try:
            # Test rollback on exception
            with pytest.raises(ValueError, match="Test error"):
                async with get_async_session_context() as session:
                    # Create a user object without committing (using session.add directly)
                    user_obj = User(
                        email="rollback@example.com",
                        full_name="Rollback Test User",
                        hashed_password="testhash",
                    )
                    session.add(user_obj)

                    # Force an error to trigger rollback before commit
                    raise ValueError("Test error")

            # Verify the transaction was rolled back
            async with test_session_maker() as verify_session:
                found_user = await user_repository.get_by_email(
                    verify_session, email="rollback@example.com"
                )
                assert found_user is None  # Should be None due to rollback

        finally:
            # Restore original session maker
            db_module.async_session_maker = original_session_maker
            await test_engine.dispose()

    @pytest.mark.asyncio
    async def test_get_async_session_generator(self) -> None:
        """Test the get_async_session generator function."""
        from neodyme.core.database import get_async_session

        # Test that the generator yields a session
        async for session in get_async_session():
            assert isinstance(session, AsyncSession)
            # Test that we can use the session
            count = await user_repository.count(session)
            assert isinstance(count, int)
            break  # Only test the first yielded session