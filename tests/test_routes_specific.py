"""Specific tests to improve route coverage."""
import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from neodyme.models import UserCreate
from neodyme.repositories import user_repository


class TestRoutesCoverage:
    """Tests specifically designed to improve route coverage."""

    @pytest.mark.asyncio
    async def test_create_user_success_then_conflict(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test successful user creation followed by conflict."""

        # Test successful creation (should hit line 22)
        user_data = {
            "email": "unique@coverage.com",
            "full_name": "Unique User",
            "password": "uniquepass123",
        }

        response1 = await async_client.post("/api/v1/users/", json=user_data)
        assert response1.status_code == 201
        data = response1.json()
        assert data["email"] == user_data["email"]
        assert data["full_name"] == user_data["full_name"]
        assert "id" in data

        # Test conflict on same email (should hit lines 18-19)
        response2 = await async_client.post("/api/v1/users/", json=user_data)
        assert response2.status_code == 409
        assert "Email already registered" in response2.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_user_with_existing_db_user(
        self, async_client: AsyncClient, test_session: AsyncSession
    ) -> None:
        """Test conflict when user already exists in database."""

        # Create user directly in database first
        existing_user = UserCreate(
            email="preexisting@coverage.com",
            full_name="Pre-existing User",
            password="preexistingpass123",
        )
        await user_repository.create(test_session, obj_in=existing_user)

        # Try to create via API with same email (should hit lines 18-19)
        conflicting_data = {
            "email": "preexisting@coverage.com",
            "full_name": "Conflicting User",
            "password": "conflictingpass123",
        }

        response = await async_client.post("/api/v1/users/", json=conflicting_data)
        assert response.status_code == 409
        assert "Email already registered" in response.json()["detail"]

    def test_create_user_success_sync(self, client: TestClient) -> None:
        """Test successful user creation with sync client."""
        user_data = {
            "email": "sync@coverage.com",
            "full_name": "Sync User",
            "password": "syncpass123",
        }

        response = client.post("/api/v1/users/", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["full_name"] == user_data["full_name"]
        assert "id" in data