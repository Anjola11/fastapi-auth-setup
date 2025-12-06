from pydantic import BaseModel, EmailStr
from datetime import datetime
import uuid
from src.emailServices.schemas import OtpTypes

# --- INPUT SCHEMAS ---

class UserInput(BaseModel):
    fullName: str
    email: EmailStr
    password: str

class LoginInput(BaseModel):
    email: EmailStr
    password: str

class VerifyOtpInput(BaseModel):
    user_id: uuid.UUID
    otp: str
    otp_type: OtpTypes

class ForgotPasswordInput(BaseModel):
    email: EmailStr

class ResetPasswordInput(BaseModel):
    new_password: str
    token: str

# --- OUTPUT/RESPONSE SCHEMAS ---

class User(BaseModel):
    user_id: uuid.UUID 
    fullName: str
    email: EmailStr 
    email_verified: bool 
    created_at: datetime 

class UserCreateResponse(BaseModel):
    success: bool
    message: str
    data: User

class LoginData(BaseModel):
    user_id: uuid.UUID
    fullName: str
    email: EmailStr
    email_verified: bool
    created_at: datetime
    access_token: str
    refresh_token: str

class LoginResponse(BaseModel):
    success: bool
    message: str
    data: LoginData

class ForgotPasswordResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}