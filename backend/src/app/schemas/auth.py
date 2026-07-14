"""Authentication request and response schemas."""

from pydantic import BaseModel, EmailStr, Field

from app.models.user import ThemePreference, UserRole


class LoginRequest(BaseModel):
    """Login request with email and password."""

    email: EmailStr
    password: str


class PasswordChangeRequest(BaseModel):
    """Self-service password change; requires the current password."""

    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """User information response."""

    id: int
    email: str
    role: UserRole
    is_active: bool
    theme_preference: ThemePreference
    totp_enabled: bool = False
    backup_codes_remaining: int = 0

    model_config = {"from_attributes": True}


class UserThemeUpdateRequest(BaseModel):
    """Update theme preference for current user."""

    theme_preference: ThemePreference
