"""Tests for the self-service password change endpoint."""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_password
from app.models.user import User


class TestChangePassword:
    async def test_requires_auth(self, client: AsyncClient):
        resp = await client.post(
            "/api/auth/change-password",
            json={"current_password": "x", "new_password": "longenough1"},
        )
        assert resp.status_code == 401

    async def test_wrong_current_password(
        self, client: AsyncClient, admin_headers: dict[str, str]
    ):
        resp = await client.post(
            "/api/auth/change-password",
            headers=admin_headers,
            json={"current_password": "wrong", "new_password": "longenough1"},
        )
        assert resp.status_code == 400

    async def test_short_new_password_rejected(
        self, client: AsyncClient, admin_headers: dict[str, str]
    ):
        resp = await client.post(
            "/api/auth/change-password",
            headers=admin_headers,
            json={"current_password": "admin", "new_password": "short"},
        )
        assert resp.status_code == 422

    async def test_change_succeeds_and_invalidates_token(
        self,
        client: AsyncClient,
        admin_headers: dict[str, str],
        admin_user: User,
        db_session: AsyncSession,
    ):
        resp = await client.post(
            "/api/auth/change-password",
            headers=admin_headers,
            json={
                "current_password": "adminpass123",
                "new_password": "brand-new-password-1",
            },
        )
        assert resp.status_code == 204

        await db_session.refresh(admin_user)
        assert verify_password("brand-new-password-1", admin_user.password_hash)

        # token_version bump invalidates the old token
        me = await client.get("/api/auth/me", headers=admin_headers)
        assert me.status_code == 401
