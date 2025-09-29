import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from neodyme.models import UserCreate
from neodyme.repositories import user_repository


class TestUserAPI:
    """Test user API endpoints."""

    @pytest.mark.asyncio
    async def test_create_user(self, async_client: AsyncClient) -> None:
        """Test creating a new user."""
        user_data = {
            "email": "test@example.com",
            "full_name": "Test User",
            "password": "testpassword123",
        }

        response = await async_client.post("/api/v1/users/", json=user_data)

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["full_name"] == user_data["full_name"]
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data
        assert "hashed_password" not in data

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, async_client: AsyncClient) -> None:
        """Test creating a user with duplicate email."""
        user_data = {
            "email": "duplicate@example.com",
            "full_name": "Test User",
            "password": "testpassword123",
        }

        # Create first user
        response1 = await async_client.post("/api/v1/users/", json=user_data)
        assert response1.status_code == 201

        # Try to create second user with same email
        response2 = await async_client.post("/api/v1/users/", json=user_data)
        assert response2.status_code == 409
        assert "Email already registered" in response2.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_user_email_already_exists_conflict(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test creating a user when email already exists in database."""
        # First, create a user directly via repository
        existing_user_create = UserCreate(
            email="existing@example.com",
            full_name="Existing User",
            password="existingpass123",
        )
        await user_repository.create(test_session, obj_in=existing_user_create)

        # Try to create another user with the same email via API
        new_user_data = {
            "email": "existing@example.com",
            "full_name": "New User",
            "password": "newpass123",
        }

        response = await async_client.post("/api/v1/users/", json=new_user_data)

        assert response.status_code == 409
        assert "Email already registered" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_user(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test getting a user by ID."""
        # Create a user first
        user_create = UserCreate(
            email="gettest@example.com",
            full_name="Get Test User",
            password="testpassword123",
        )
        user = await user_repository.create(test_session, obj_in=user_create)

        response = await async_client.get(f"/api/v1/users/{user.id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == user.id
        assert data["email"] == user.email
        assert data["full_name"] == user.full_name

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, async_client: AsyncClient) -> None:
        """Test getting a non-existent user."""
        response = await async_client.get("/api/v1/users/999")

        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_users(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test getting list of users."""
        # Create test users
        users_data = [
            UserCreate(
                email=f"user{i}@example.com",
                full_name=f"User {i}",
                password="testpassword123",
            )
            for i in range(3)
        ]

        for user_data in users_data:
            await user_repository.create(test_session, obj_in=user_data)

        response = await async_client.get("/api/v1/users/")

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 3

    @pytest.mark.asyncio
    async def test_update_user(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test updating a user."""
        # Create a user first
        user_create = UserCreate(
            email="updatetest@example.com",
            full_name="Update Test User",
            password="testpassword123",
        )
        user = await user_repository.create(test_session, obj_in=user_create)

        update_data = {
            "full_name": "Updated Test User",
            "email": "updated@example.com",
        }

        response = await async_client.put(f"/api/v1/users/{user.id}", json=update_data)

        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == update_data["full_name"]
        assert data["email"] == update_data["email"]

    @pytest.mark.asyncio
    async def test_delete_user(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test deleting a user."""
        # Create a user first
        user_create = UserCreate(
            email="deletetest@example.com",
            full_name="Delete Test User",
            password="testpassword123",
        )
        user = await user_repository.create(test_session, obj_in=user_create)

        response = await async_client.delete(f"/api/v1/users/{user.id}")

        assert response.status_code == 204

        # Verify user is deleted
        get_response = await async_client.get(f"/api/v1/users/{user.id}")
        assert get_response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, async_client: AsyncClient) -> None:
        """Test deleting a non-existent user."""
        response = await async_client.delete("/api/v1/users/999")

        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, async_client: AsyncClient) -> None:
        """Test updating a non-existent user."""
        update_data = {"full_name": "Updated Name"}

        response = await async_client.put("/api/v1/users/999", json=update_data)

        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_user_email_conflict(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test updating a user with an email that already exists."""
        # Create two users with unique emails for this test
        user1_create = UserCreate(
            email="conflict1@example.com",
            full_name="User 1",
            password="testpassword123",
        )
        user1 = await user_repository.create(test_session, obj_in=user1_create)

        user2_create = UserCreate(
            email="conflict2@example.com",
            full_name="User 2",
            password="testpassword123",
        )
        user2 = await user_repository.create(test_session, obj_in=user2_create)

        # Try to update user2 with user1's email
        update_data = {"email": "conflict1@example.com"}

        response = await async_client.put(f"/api/v1/users/{user2.id}", json=update_data)

        assert response.status_code == 409
        assert "Email already registered" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_user_with_password(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test updating a user with a new password."""
        # Create a user first
        user_create = UserCreate(
            email="passwordtest@example.com",
            full_name="Password Test User",
            password="oldpassword123",
        )
        user = await user_repository.create(test_session, obj_in=user_create)
        original_hashed_password = user.hashed_password

        update_data = {
            "password": "completelydifferentpassword456",
            "full_name": "Updated Password Test User",
        }

        response = await async_client.put(f"/api/v1/users/{user.id}", json=update_data)

        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == update_data["full_name"]

        # Verify password was actually updated by checking the database
        updated_user = await user_repository.get(test_session, id=user.id)
        assert updated_user.hashed_password != original_hashed_password

    def test_health_check(self, client: TestClient) -> None:
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}


class TestUserRepository:
    """Test user repository operations."""

    @pytest.mark.asyncio
    async def test_get_by_email(self, test_session: AsyncSession) -> None:
        """Test getting user by email."""
        user_create = UserCreate(
            email="emailtest@example.com",
            full_name="Email Test User",
            password="testpassword123",
        )
        created_user = await user_repository.create(test_session, obj_in=user_create)

        found_user = await user_repository.get_by_email(
            test_session, email="emailtest@example.com"
        )

        assert found_user is not None
        assert found_user.id == created_user.id
        assert found_user.email == created_user.email

    @pytest.mark.asyncio
    async def test_get_by_email_not_found(self, test_session: AsyncSession) -> None:
        """Test getting user by non-existent email."""
        found_user = await user_repository.get_by_email(
            test_session, email="nonexistent@example.com"
        )

        assert found_user is None

    @pytest.mark.asyncio
    async def test_create_user_hashes_password(
        self, test_session: AsyncSession
    ) -> None:
        """Test that user creation hashes the password."""
        user_create = UserCreate(
            email="hashtest@example.com",
            full_name="Hash Test User",
            password="plaintextpassword",
        )

        created_user = await user_repository.create(test_session, obj_in=user_create)

        assert created_user.hashed_password != "plaintextpassword"
        assert len(created_user.hashed_password) == 64  # SHA256 hex length

    @pytest.mark.asyncio
    async def test_count_users(self, test_session: AsyncSession) -> None:
        """Test counting users in the repository."""
        # Create some test users
        users_data = [
            UserCreate(
                email=f"count{i}@example.com",
                full_name=f"Count User {i}",
                password="testpassword123",
            )
            for i in range(5)
        ]

        for user_data in users_data:
            await user_repository.create(test_session, obj_in=user_data)

        count = await user_repository.count(test_session)
        assert count >= 5  # At least the 5 we just created

    @pytest.mark.asyncio
    async def test_get_multi_with_pagination(self, test_session: AsyncSession) -> None:
        """Test getting multiple users with pagination."""
        # Create test users
        users_data = [
            UserCreate(
                email=f"paginate{i}@example.com",
                full_name=f"Paginate User {i}",
                password="testpassword123",
            )
            for i in range(10)
        ]

        for user_data in users_data:
            await user_repository.create(test_session, obj_in=user_data)

        # Test pagination
        first_page = await user_repository.get_multi(test_session, skip=0, limit=5)
        second_page = await user_repository.get_multi(test_session, skip=5, limit=5)

        assert len(first_page) <= 5
        assert len(second_page) <= 5

        # Ensure different users (no overlap)
        first_page_ids = {user.id for user in first_page}
        second_page_ids = {user.id for user in second_page}
        assert first_page_ids.isdisjoint(second_page_ids)

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user(self, test_session: AsyncSession) -> None:
        """Test deleting a user that doesn't exist."""
        result = await user_repository.delete(test_session, id=99999)
        assert result is None

    @pytest.mark.asyncio
    async def test_update_user_dict_input(self, test_session: AsyncSession) -> None:
        """Test updating a user with dictionary input instead of Pydantic model."""
        # Create a user first
        user_create = UserCreate(
            email="dictupdate@example.com",
            full_name="Dict Update User",
            password="testpassword123",
        )
        created_user = await user_repository.create(test_session, obj_in=user_create)

        # Update with dictionary
        update_dict = {"full_name": "Updated with Dict"}
        updated_user = await user_repository.update(
            test_session, db_obj=created_user, obj_in=update_dict
        )

        assert updated_user.full_name == "Updated with Dict"
        assert updated_user.email == created_user.email  # Unchanged

    @pytest.mark.asyncio
    async def test_get_user_not_found_returns_none(self, test_session: AsyncSession) -> None:
        """Test that getting a non-existent user returns None."""
        user = await user_repository.get(test_session, id=99999)
        assert user is None
