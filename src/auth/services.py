"""Authentication service layer.

This module implements the business logic for user authentication operations
including signup, login, and OTP verification. It handles user model selection
based on role (planner/vendor) and manages token generation for authenticated
sessions.
"""

from sqlmodel import select
from src.auth.models import User, SignupOtp, ForgotPasswordOtp
from src.auth.schemas import (
    UserInput, VerifyOtpInput, LoginInput, ForgotPasswordInput, 
    ResetPasswordInput, RenewAccessTokenInput, ResendOtpInput
)
from src.emailServices.schemas import OtpTypes
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi import HTTPException, status, UploadFile, BackgroundTasks
from sqlalchemy.exc import DatabaseError
from src.utils.auth import generate_password_hash, verify_password_hash, create_token, decode_token
from datetime import datetime, timezone, timedelta
import uuid
from src.db.redis import redis_client
from src.file_uploads.services import FileUploadServices
from src.emailServices.services import EmailServices

file_upload_service = FileUploadServices()
email_services = EmailServices()

# Token expiration configurations
access_token_expiry = timedelta(hours=2)
refresh_token_expiry = timedelta(days=3)
reset_password_expiry = timedelta(minutes=5)

class AuthServices:
    """Service class for authentication operations.
    
    Provides methods for user registration, login, and OTP verification.
    Handles role-based model selection and token generation.
    """

    async def get_user_by_email(self, email: str, session: AsyncSession):
        """
        Helper function to retrieve a User object by email.
        Returns the User instance if found, otherwise None.
        """
        try:
            statement = select(User).where(User.email == email)
            result = await session.exec(statement)
            return result.first()
        except DatabaseError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during user lookup"
            )

    async def checkUserExists(self, userInput: UserInput, session: AsyncSession):
        """Checks if a user already exists during signup."""
        user = await self.get_user_by_email(userInput.email, session)

        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists"
            )
        return None

    async def signupUser(self, userInput: UserInput, session: AsyncSession):
        # Verify user doesn't already exist
        await self.checkUserExists(userInput, session)
        
        # Hash password before storing
        hashed_password = generate_password_hash(userInput.password)

        # Create new user instance
        new_user = User(
            fullName=userInput.fullName,
            email=userInput.email,
            password_hash=hashed_password,
        )

        try:
            # Persist user to database
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)

            return new_user

        except DatabaseError:
            # Rollback transaction on database error
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
    
    async def verify_otp(self, otp_input: VerifyOtpInput, session: AsyncSession):
        """Verify a user's OTP and activate their account."""
        
        model = SignupOtp if otp_input.otp_type == OtpTypes.SIGNUP else ForgotPasswordOtp
        
        # Retrieve the most recent OTP record for this user
        otp_statement = (select(model)
                       .where(model.user_id == otp_input.user_id)
                       .order_by(model.created_at.desc()))
        
        result = await session.exec(otp_statement)
        latest_otp_record = result.first()

        # Validate OTP record exists
        if not latest_otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="No OTP found for this user"
            )
        
        # Validate OTP code matches
        if latest_otp_record.otp != otp_input.otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Invalid OTP code"
            )

        # Check if OTP has expired
        if datetime.now(timezone.utc) > latest_otp_record.expires:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP expired, please request a new one"
            )
        
        if otp_input.otp_type == OtpTypes.SIGNUP:
            # Retrieve the user record using ID 
            user_statement = select(User).where(User.user_id == otp_input.user_id)
            result = await session.exec(user_statement)
            user = result.first()

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, 
                    detail="User not found"
                )
        
            try:
                # Mark user as verified and delete used OTP
                user.email_verified = True
                session.add(user)
                await session.delete(latest_otp_record)
                await session.commit()
                await session.refresh(user)
                return user

            except DatabaseError:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error"
                )
        
        elif otp_input.otp_type == OtpTypes.FORGOTPASSWORD:
            try:
                await session.delete(latest_otp_record)
                await session.commit()
                return {
                    "user_id": latest_otp_record.user_id,
                }
            except DatabaseError:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error"
                )

    async def resend_otp(self, resend_otp_input: ResendOtpInput,session: AsyncSession, background_tasks = BackgroundTasks):
        """Resends an OTP to the user if applicable."""
        
        # Check if user exists using Helper
        user = await self.get_user_by_email(resend_otp_input.email, session)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User with this email does not exist"
            )
        
        datetime_now = datetime.now(timezone.utc)

        # Logic for Signup Resend
        if resend_otp_input.otp_type == OtpTypes.SIGNUP:
            if user.email_verified:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User is already verified. Please login."
                )
            
            signup_otp_satatement = select(SignupOtp).where(SignupOtp.user_id == user.user_id).order_by(
                SignupOtp.created_at.desc()
            )
            result = await session.exec(signup_otp_satatement)
            signup_otp = result.first()

            if signup_otp and signup_otp.expires > datetime_now:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You already requested for an otp, check your email"
                )
            
            otp_record = await email_services.save_otp(user.user_id, session, type =OtpTypes.SIGNUP)

            background_tasks.add_task(
            email_services.send_email_verification_otp, 
            user.email, 
            otp_record.otp, 
            user.fullName
        )

            
            return {
                "success": True,
                "message": "Signup OTP resent successfully", 
                "user_id": user.user_id
            }

        # Logic for Forgot Password Resend
        elif resend_otp_input.otp_type == OtpTypes.FORGOTPASSWORD:
            
           
            forgot_password_otp_satatement = select(ForgotPasswordOtp).where(ForgotPasswordOtp.user_id == user.user_id).order_by(
                ForgotPasswordOtp.created_at.desc()
            )
            result = await session.exec(forgot_password_otp_satatement)
            forgot_password_otp = result.first()

            if forgot_password_otp and forgot_password_otp.expires > datetime_now:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You already requested for an otp, check your email"
                )
            
            otp_record = await email_services.save_otp(user.user_id, session, type =OtpTypes.FORGOTPASSWORD)

            background_tasks.add_task(
            email_services.send_forgot_password_otp, 
            user.email, 
            otp_record.otp, 
            user.fullName
        )
            return {
                "success": True, 
                "message": "Password reset OTP resent successfully",
                "user_id": user.user_id
            }
            
    async def loginUser(self, loginInput: LoginInput, session: AsyncSession):
        """Authenticate a user and generate access tokens."""
        
        # Query user by email using Helper
        user = await self.get_user_by_email(loginInput.email, session)
        
        # Reusable exception for invalid credentials
        INVALID_CREDENTIALS = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Credentials"
        )

        # Validate user exists
        if not user:
            raise INVALID_CREDENTIALS
        
        if not user.email_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Please verify your account before you can login"
            )

        # Verify password hash matches
        verified_password = verify_password_hash(loginInput.password, user.password_hash)

        if not verified_password:
            raise INVALID_CREDENTIALS

        # Generate authentication tokens
        user_dict = user.model_dump()
        access_token = create_token(user_dict, access_token_expiry, type="access")
        refresh_token = create_token(user_dict, refresh_token_expiry, type="refresh")
        
        # Combine user data with tokens
        user_details = {
            **user_dict, 
            'access_token': access_token,
            'refresh_token': refresh_token,
            'profile_picture_url': user.profile_picture_url
        }
        
        return user_details
    
    async def forgotPassword(self, forgotPasswordInput: ForgotPasswordInput, session: AsyncSession):
        
        #Query user by email using Helper
        user = await self.get_user_by_email(forgotPasswordInput.email, session)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is not registered"
            ) 
        
        return user
    
    async def resetPassword(self, resetPasswordInput: ResetPasswordInput, session: AsyncSession):
        # Decode and Validate Token
        token_decode = decode_token(resetPasswordInput.reset_token)

        # Check Token Type
        if token_decode.get('type') != "reset":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

        # Extract User ID from Token
        user_id_from_token = token_decode.get('sub')

        statement = select(User).where(User.user_id == uuid.UUID(user_id_from_token))
        result = await session.exec(statement)
        user = result.first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Update Password
        new_hashed_password = generate_password_hash(resetPasswordInput.new_password)
        user.password_hash = new_hashed_password

        try:
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user
        except DatabaseError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
        
    async def upload_profile_picture(self, user_id: str, file: UploadFile, session: AsyncSession):
        user_statement = select(User).where(User.user_id == uuid.UUID(user_id))
        result = await session.exec(user_statement)

        user = result.first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        old_profile_picture_id = user.profile_picture_id
        profile_picture_id = await file_upload_service.upload_image(old_profile_picture_id, file, type="profile")

        user.profile_picture_id = profile_picture_id

        try:
            await session.commit()
            await session.refresh(user)

            return user
        except DatabaseError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
        
    async def renewAccessToken(self, renewAccessTokenInput: RenewAccessTokenInput, session: AsyncSession):
       
        refresh_token_str = renewAccessTokenInput.refresh_token
        
        token_decode = decode_token(refresh_token_str)

        if token_decode.get('type') != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token type"
            )

        user_id = token_decode.get("sub") 
        statement = select(User).where(User.user_id == uuid.UUID(user_id))
        result = await session.exec(statement)
        user = result.first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_data = {
            "user_id": user.user_id,
            "email": user.email
        }

        new_token = create_token(user_data, expiry_delta=access_token_expiry, type="access")
        
        return {
            "access_token" : new_token
        }
    
    async def add_token_to_blocklist(self, token):
        token_decoded = decode_token(token)
        token_id = token_decoded.get('jti')
        exp_timestamp = token_decoded.get('exp')

        current_time = datetime.now(timezone.utc).timestamp()
        time_to_live = int(exp_timestamp - current_time)

        if time_to_live > 0:
            await redis_client.setex(name=token_id, time=time_to_live, value="true")
        
    async def is_token_blacklisted(self, jti: str) -> bool:
        result = await redis_client.get(jti)
        return result is not None