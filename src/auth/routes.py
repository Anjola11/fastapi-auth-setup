"""Authentication API routes.

This module defines the REST API endpoints for user authentication workflows.
"""

from fastapi import APIRouter, Depends, status, BackgroundTasks, File, UploadFile
from src.auth.services import AuthServices
from src.auth.schemas import (
    UserInput, 
    UserCreateResponse, 
    VerifyOtpInput, 
    ResendOtpInput,
    ResendOtpResponse,
    LoginInput, 
    LoginResponse, 
    ForgotPasswordInput, 
    ForgotPasswordResponse, 
    ResetPasswordInput,
    RenewAccessTokenInput,
    RenewAccessTokenResponse,
    LogoutResponse
)
from sqlmodel.ext.asyncio.session import AsyncSession
from src.db.main import get_Session
from src.emailServices.services import EmailServices
from src.emailServices.schemas import OtpTypes
from src.utils.auth import create_token
from datetime import timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from src.utils.auth import get_current_user


reset_password_expiry = timedelta(minutes=5)

# Initialize router for auth endpoints
authRouter = APIRouter()

# Initialize service instances
authServices = AuthServices()
emailServices = EmailServices()
security = HTTPBearer()

@authRouter.post("/signup", status_code=status.HTTP_201_CREATED, response_model=UserCreateResponse)
async def signupUser(
    userInput: UserInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_Session)
):
    # 1. Create the user in the database
    new_user = await authServices.signupUser(userInput, session)
    user_id = new_user.user_id
    
    
    otp_record = await emailServices.save_otp(user_id, session, type=OtpTypes.SIGNUP)
    
    # 3. Send verification email in background
    background_tasks.add_task(
        emailServices.send_email_verification_otp, 
        userInput.email, 
        otp_record.otp, 
        userInput.fullName
    )
    
    return {
        "success": True,
        "message": "signup successful, an otp has been sent to your email to verify your account",
        "data": new_user
    }

@authRouter.post("/verify_otp", status_code=status.HTTP_200_OK)
async def verifyOtp(
    otp_input: VerifyOtpInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_Session)
):
    """Verify user's email or password reset OTP."""
    
    # 1. Verify OTP
    # Returns a User object (Signup) or a dict {'user_id': ...} (Forgot Password)
    result = await authServices.verify_otp(otp_input, session)
    
    # 2. Case A: SIGNUP Logic
    if otp_input.otp_type == OtpTypes.SIGNUP:
        # Send Welcome Email
        background_tasks.add_task(
            emailServices.send_welcome_email,
            result.email,
            result.fullName
        )
        
        return {
            "success": True,
            "message": "otp verified, proceed to login",
            "data": result
        }

    # 3. Case B: FORGOT PASSWORD Logic
    elif otp_input.otp_type == OtpTypes.FORGOTPASSWORD:
        # Create a reset token using the user_id from the result
        # result is a dict: {'user_id': UUID(...)}
        reset_password_token = create_token(result, reset_password_expiry, type="reset")
        
        # Add token to response data
        result['reset_token'] = reset_password_token
        
        return {
            "success": True,
            "message": "OTP verified successfully",
            "data": result
        }
    
@authRouter.post("/resend-otp",response_model=ResendOtpResponse, status_code=status.HTTP_200_OK)
async def resendOtp(resend_otp_input: ResendOtpInput,background_tasks: BackgroundTasks,  
    session: AsyncSession = Depends(get_Session)):
    otp = await authServices.resend_otp(resend_otp_input,session, background_tasks)

    return otp

@authRouter.post("/login", status_code=status.HTTP_200_OK, response_model=LoginResponse)
async def loginUser(
    loginInput: LoginInput, 
    session: AsyncSession = Depends(get_Session)
):
    user = await authServices.loginUser(loginInput, session)
    
    return {
        "success": True,
        "message": "login successful",
        "data": user
    }

@authRouter.post("/forgot_password", status_code=status.HTTP_201_CREATED, response_model=ForgotPasswordResponse)
async def forgotPassword(
    forgotPasswordInput: ForgotPasswordInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_Session)
):
    # 1. Check user exists
    user = await authServices.forgotPassword(forgotPasswordInput, session)
    user_id = user.user_id
    
    # 2. Generate and save OTP
    otp_record = await emailServices.save_otp(user_id, session, type=OtpTypes.FORGOTPASSWORD)
    
    # 3. Send email in background
    background_tasks.add_task(
        emailServices.send_forgot_password_otp, 
        user.email, 
        otp_record.otp, 
        user.fullName
    )
    
    return {
        "success": True,
        "message": "an otp to reset password has been sent to your email",
        "data": {"user_id": user_id}
    }

@authRouter.patch("/reset_password", status_code=status.HTTP_200_OK, response_model=UserCreateResponse)
async def resetPassword( 
    resetPasswordInput: ResetPasswordInput, 
    session: AsyncSession = Depends(get_Session)
):
    # 1. Update the password
    user = await authServices.resetPassword(resetPasswordInput, session)
   
    return {
        "success": True,
        "message": "password reset successful, proceed to login",
        "data": user
    }

@authRouter.post("/upload-profile-picture/", status_code=status.HTTP_201_CREATED, response_model=UserCreateResponse)
async def upload_profile_picture(
    user_id=Depends(get_current_user), 
    session: AsyncSession = Depends(get_Session),
    file: UploadFile = File(...)
    ):
    user_new_data = await authServices.upload_profile_picture(user_id, file, session)

    return {
        "success": True,
        "message": "profile picture uploaded succesfully",
        "data": user_new_data
    }

@authRouter.post("/renew_access_token", status_code=status.HTTP_201_CREATED, response_model=RenewAccessTokenResponse)
async def renewAccessToken(
    renewAccessTokenInput: RenewAccessTokenInput,
    session: AsyncSession = Depends(get_Session) 
):
    
    new_token = await authServices.renewAccessToken(renewAccessTokenInput, session)
    
    return {
        "success": True,
        "message": "access token renewed successfully",
        "data": new_token
    }

@authRouter.post("/logout", status_code=status.HTTP_200_OK, response_model=LogoutResponse)
async def logout(
        token_auth: HTTPAuthorizationCredentials = Depends(security)
):
    token = token_auth.credentials

    await authServices.add_token_to_blocklist(token)
    
    return {
        "success": True,
        "message": "Logged out successfully",
        "data": {}
    }