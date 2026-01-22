"""Pydantic schemas for authentication API.

This module defines the request and response models used in authentication
endpoints. Validates data for the simplified, single-user-table architecture.
"""

from pydantic import BaseModel, EmailStr, ConfigDict, field_validator
from datetime import datetime
import uuid
from src.emailServices.schemas import OtpTypes
from typing import Optional
import re

# --- INPUT SCHEMAS ---

class UserInput(BaseModel):
    """Payload for user registration."""
    fullName: str
    email: EmailStr
    password: str 

    @field_validator("password")
    @classmethod
    def validate(cls, value:str):
        if len(value) < 8:
            raise ValueError("Password must have a minimum length of 8 characters")
        
        if not re.search(r'[A-Z]', value):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', value):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', value):
            raise ValueError('Password must contain at least one digit')
        return value  # Fixed: was 'v' instead of 'value'

class LoginInput(BaseModel):
    """Payload for user login."""
    email: EmailStr
    password: str

class VerifyOtpInput(BaseModel):
    """Payload for verifying email/password OTPs."""
    user_id: uuid.UUID
    otp: str
    otp_type: OtpTypes

class ResendOtpInput(BaseModel):
    """Payload for resending email/password OTPs."""
    email: EmailStr
    otp_type: OtpTypes

class ResendOtpResponse(BaseModel):
    success: bool
    message: str
    user_id: uuid.UUID

class ForgotPasswordInput(BaseModel):
    """Payload for initiating password reset."""
    email: EmailStr


# --- OUTPUT/RESPONSE SCHEMAS ---

class User(BaseModel):
    """Base user model for responses (excludes sensitive data)."""
    user_id: uuid.UUID 
    fullName: str
    email: EmailStr 
    email_verified: bool 
    profile_picture_url: str
    created_at: datetime 

    model_config = ConfigDict(from_attributes=True)

class UserCreateResponse(BaseModel):
    """Response structure for successful signup."""
    success: bool
    message: str
    data: User

class LoginData(BaseModel):
    """Data returned upon successful login."""
    user_id: uuid.UUID
    fullName: str
    email: EmailStr
    email_verified: bool
    profile_picture_url: str
    created_at: datetime
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class LoginResponse(BaseModel):
    """Response structure for successful login."""
    success: bool
    message: str
    data: LoginData

class ForgotPasswordResponse(BaseModel):
    """Response structure for forgot password request."""
    success: bool
    message: str
    data: dict = {}

class ResetPasswordInput(BaseModel):
    new_password: str
    reset_token: str
    
    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str):
        """Validate new password strength (same requirements as signup)."""
        if len(value) < 8:
            raise ValueError("Password must have a minimum length of 8 characters")
        if not re.search(r'[A-Z]', value):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', value):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', value):
            raise ValueError('Password must contain at least one digit')
        return value
 
class RenewAccessTokenInput(BaseModel):
    refresh_token: str

class RenewAccessTokenResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}

class LogoutInput(BaseModel):
    refresh_token: Optional[str] = None
class LogoutResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}