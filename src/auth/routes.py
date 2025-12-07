from fastapi import APIRouter, Depends, status, BackgroundTasks
from src.auth.services import AuthServices
from src.auth.schemas import (
    UserInput, 
    UserCreateResponse, 
    VerifyOtpInput, 
    LoginInput, 
    LoginResponse, 
    ForgotPasswordInput, 
    ForgotPasswordResponse, 
    ResetPasswordInput,
    RenewAccessTokenInput,
    RenweAccessTokenResponse
)
from sqlmodel.ext.asyncio.session import AsyncSession
from src.db.main import get_Session
from src.emailServices.services import EmailServices
from src.emailServices.schemas import OtpTypes
from src.utils.auth import create_token
from datetime import timedelta

reset_password_expiry = timedelta(minutes=5)

authRouter = APIRouter()
authServices = AuthServices()
emailServices = EmailServices()

@authRouter.post("/signup", status_code=status.HTTP_201_CREATED, response_model=UserCreateResponse)
async def signupUser(
    userInput: UserInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_Session)
):
    new_user = await authServices.signupUser(userInput, session)
    user_id = new_user.user_id
    
    otp_record = await emailServices.save_otp(user_id, session, type="signup")
    
    background_tasks.add_task(
        emailServices.send_email_verification_otp, 
        userInput.email, 
        otp_record.otp, 
        userInput.fullName
    )
    
    return {
        "success": True,
        "message": "Signup successful, check email for OTP",
        "data": new_user
    }

@authRouter.post("/verify_otp", status_code=status.HTTP_200_OK)
async def verifyOtp(
    otp_input: VerifyOtpInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_Session)
):
    result = await authServices.verify_otp(otp_input, session)
    
    if otp_input.otp_type == OtpTypes.SIGNUP:
        background_tasks.add_task(
            emailServices.send_welcome_email,
            result.email,
            result.fullName
        )
        return {
            "success": True,
            "message": "OTP verified, proceed to login",
            "data": result
        }

    elif otp_input.otp_type == OtpTypes.FORGOTPASSWORD:
        reset_password_token = create_token(result, reset_password_expiry, type="reset")
        result['reset_token'] = reset_password_token
        return {
            "success": True,
            "message": "OTP verified successfully",
            "data": result
        }

@authRouter.post("/login", status_code=status.HTTP_200_OK, response_model=LoginResponse)
async def loginUser(
    loginInput: LoginInput, 
    session: AsyncSession = Depends(get_Session)
):
    user = await authServices.loginUser(loginInput, session)
    return {
        "success": True,
        "message": "Login successful",
        "data": user
    }

@authRouter.post("/forgot_password", status_code=status.HTTP_201_CREATED, response_model=ForgotPasswordResponse)
async def forgotPassword(
    forgotPasswordInput: ForgotPasswordInput, 
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_Session)
):
    user = await authServices.forgotPassword(forgotPasswordInput, session)
    user_id = user.user_id
    
    otp_record = await emailServices.save_otp(user_id, session, type="forgotPassword")
    
    background_tasks.add_task(
        emailServices.send_forgot_password_otp, 
        user.email, 
        otp_record.otp, 
        user.fullName
    )
    
    return {
        "success": True,
        "message": "OTP sent to email",
        "data": {"user_id": user_id}
    }

@authRouter.patch("/reset_password", status_code=status.HTTP_200_OK, response_model=UserCreateResponse)
async def resetPassword( 
    resetPasswordInput: ResetPasswordInput, 
    session: AsyncSession = Depends(get_Session)
):
    user = await authServices.resetPassword(resetPasswordInput, session)
    return {
        "success": True,
        "message": "Password reset successful",
        "data": user
    }

@authRouter.post("/renew_access_token", status_code=status.HTTP_201_CREATED, response_model=RenweAccessTokenResponse)
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