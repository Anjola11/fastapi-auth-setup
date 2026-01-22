"""Authentication API routes.

This module defines the REST API endpoints for user authentication workflows.
"""

from fastapi import APIRouter, Depends, status, BackgroundTasks, File, UploadFile, Response, Request, HTTPException
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
    LogoutInput,
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
from src.utils.limiter import limiter


reset_password_expiry = timedelta(minutes=5)

# Initialize router for auth endpoints
authRouter = APIRouter()

# Initialize service instances
authServices = AuthServices()
emailServices = EmailServices()
security = HTTPBearer(auto_error=False)

@authRouter.post("/signup", status_code=status.HTTP_201_CREATED, response_model=UserCreateResponse)
@limiter.limit("5/minute")
async def signupUser(
    request: Request, 
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
@limiter.limit("5/minute")
async def verifyOtp(
    request: Request, 
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
@limiter.limit("5/minute")
async def resendOtp(request: Request,
    resend_otp_input: ResendOtpInput,background_tasks: BackgroundTasks,  
    session: AsyncSession = Depends(get_Session)):
    otp = await authServices.resend_otp(resend_otp_input,session, background_tasks)

    return otp

@authRouter.post("/login", status_code=status.HTTP_200_OK, response_model=LoginResponse)
@limiter.limit("5/minute")
async def loginUser(
    loginInput: LoginInput, 
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_Session)
):
    """Authenticate user with dual-auth token delivery.
    
    Supports both web (cookies) and mobile (JSON response) clients:
    - Web: Receives tokens in httponly cookies (XSS-safe)
    - Mobile: Extracts tokens from response body for manual storage
    
    Args:
        loginInput: Email and password credentials.
        request: Request object for future client detection.
        response: Response object to set cookies.
        session: Database session.
    
    Returns:
        LoginResponse with user data and tokens in body.
    """
    user = await authServices.loginUser(loginInput, session)

    # Set httponly cookies for web clients (browser handles automatically)
    response.set_cookie(
        key="access_token",
        value=user.get('access_token'),
        httponly=True,  # Prevents JavaScript access (XSS protection)
        secure=True,  # HTTPS only
        samesite="Lax",  # CSRF protection
        max_age = 60 * 60 * 2  # 2 hours
    )
    response.set_cookie(
        key="refresh_token",
        value=user.get('refresh_token'),
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age = 60 * 60 * 24 * 3 #3 days
    )
   
    # Return tokens in body for mobile clients (cookies ignored by mobile HTTP clients)
    return {
        "success": True,
        "message": "login successful",
        "data": user  # Contains access_token & refresh_token for mobile
    }

@authRouter.post("/forgot_password", status_code=status.HTTP_201_CREATED, response_model=ForgotPasswordResponse)
@limiter.limit("5/minute")
async def forgotPassword(
    request: Request, 
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
@limiter.limit("5/minute")
async def resetPassword( 
    request: Request, 
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
@limiter.limit("5/minute")
async def upload_profile_picture(
    request: Request,
    response: Response,
    bearer_token: HTTPAuthorizationCredentials = Depends(security),
    user_id=Depends(get_current_user),  # Dual-auth handled by dependency
    session: AsyncSession = Depends(get_Session),
    file: UploadFile = File(...)
    ):
    """Upload profile picture for authenticated user (dual-auth protected).
    
    Authentication handled by get_current_user dependency which supports:
    - Mobile: Bearer token in Authorization header
    - Web: Access token in httponly cookie
    
    Args:
        request: Request object (for get_current_user dependency).
        response: Response object.
        bearer_token: Optional bearer token (for get_current_user dependency).
        user_id: Extracted from token by get_current_user dependency.
        session: Database session.
        file: Profile picture file to upload.
    
    Returns:
        UserCreateResponse with updated user data including new profile picture URL.
    """
    user_new_data = await authServices.upload_profile_picture(user_id, file, session)

    return {
        "success": True,
        "message": "profile picture uploaded succesfully",
        "data": user_new_data
    }

@authRouter.post("/renew_access_token", status_code=status.HTTP_201_CREATED, response_model=RenewAccessTokenResponse)
@limiter.limit("5/minute")
async def renewAccessToken(
    request: Request,
    response: Response,
    bearer_token: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_Session) 
):
    """Renew access token using refresh token with dual-auth support.
    
    Detects client type from refresh token source and responds accordingly:
    - Web (cookies): Returns new tokens in cookies and empty response body
    - Mobile (bearer): Returns new tokens in response body
    
    Args:
        request: Request object to access cookie-based refresh tokens.
        response: Response object to set new cookies for web clients.
        bearer_token: Optional bearer token for mobile clients.
        session: Database session.
    
    Returns:
        RenewAccessTokenResponse with new tokens (format depends on client type).
    
    Raises:
        HTTPException: If refresh token missing or invalid.
    """
    token = None

    # Dual-auth: Extract refresh token from bearer header or cookies
    bearer_raw = bearer_token.credentials
    cookie_raw = request.cookies.get('refresh_token')

    # Priority: Bearer token first, fallback to cookies
    token = bearer_raw  or cookie_raw
    if token == None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )

    # Generate new access and refresh tokens (rotates refresh token for security)
    new_token = await authServices.renewAccessToken(token, session)

    # Web client (cookie-based): Set new tokens in cookies
    if cookie_raw and not bearer_raw:

        response.set_cookie(
            key="access_token",
            value=new_token.get('access_token'),
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=60 * 60 * 2  # 2 hours (matches token expiry)
        )
        response.set_cookie(
            key="refresh_token",
            value=new_token.get('refresh_token'),
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=60 * 60 * 24 * 3  # 3 days (matches token expiry)
        )
        # Return empty data; tokens delivered via cookies
        return {
            "success": True,
            "message": "access token renewed successfully",
            "data": {}  # Empty body for web clients
        }
    
    # Mobile client (bearer-based): Return tokens in response body
    if bearer_raw and not cookie_raw:
        return {
            "success": True,
            "message": "access token renewed successfully",
            "data": new_token  # Contains access_token & refresh_token
        }


@authRouter.post("/logout", status_code=status.HTTP_200_OK, response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    logout_input: LogoutInput,
    bearer_token: HTTPAuthorizationCredentials = Depends(security),
):
    """Logout user by revoking tokens with dual-auth support.
    
    Handles token revocation for both web and mobile clients:
    - Mobile: Reads tokens from Authorization header and request body
    - Web: Reads tokens from cookies
    Both tokens are added to Redis blocklist for immediate revocation.
    
    Args:
        request: Request object to access cookies.
        response: Response object to delete cookies.
        logout_input: Optional refresh token from request body (for mobile).
        bearer_token: Optional access token from Authorization header (for mobile).
    
    Returns:
        LogoutResponse confirming successful logout.
    
    Raises:
        HTTPException: If no tokens found in either source.
    """
    
    # Dual-auth: Extract tokens from bearer/body (mobile) or cookies (web)
    if bearer_token:
        # Mobile client: Access token in header, refresh token in body
        access_token = bearer_token.credentials
        refresh_token = logout_input.refresh_token
    
    else:
        # Web client: Both tokens in cookies
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")

    if access_token == None and refresh_token == None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )

    # Revoke tokens by adding to Redis blocklist (prevents reuse)
    if access_token:
        await authServices.add_token_to_blocklist(access_token)
    if refresh_token:
        await authServices.add_token_to_blocklist(refresh_token)

    # Delete cookies (harmless for mobile, necessary for web)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    
    return {
        "success": True,
        "message": "Logged out successfully",
        "data": {}
    }