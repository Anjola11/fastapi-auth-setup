from sqlmodel import select
from src.auth.models import User, SignupOtp, ForgotPasswordOtp
from src.auth.schemas import UserInput, VerifyOtpInput, LoginInput, ForgotPasswordInput, ResetPasswordInput
from src.emailServices.schemas import OtpTypes
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi import HTTPException, status
from sqlalchemy.exc import DatabaseError
from src.utils.auth import generate_password_hash, verify_password_hash, create_token, decode_token
from datetime import datetime, timezone, timedelta
import uuid

access_token_expiry = timedelta(hours=2)
refresh_token_expiry = timedelta(days=3)

class AuthServices:

    async def checkUserExists(self, userInput: UserInput, session: AsyncSession):
        statement = select(User).where(User.email == userInput.email)
        result = await session.exec(statement)
        user = result.first()
        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail= "User already exists"
            )
        return None

    async def signupUser(self, userInput: UserInput, session: AsyncSession):
        await self.checkUserExists(userInput, session)
        hashed_password = generate_password_hash(userInput.password)
        new_user = User(
            fullName=userInput.fullName,
            email=userInput.email,
            password_hash=hashed_password,
        )
        try:
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
            return new_user
        except DatabaseError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail= "Internal server error"
            )

    async def verify_otp(self, otp_input:VerifyOtpInput, session: AsyncSession):
        if otp_input.otp_type == OtpTypes.SIGNUP:
            model = SignupOtp
        elif otp_input.otp_type == OtpTypes.FORGOTPASSWORD:
            model = ForgotPasswordOtp
        
        otp_statement = (select(model)
                     .where(model.user_id == otp_input.user_id)
                     .order_by(model.created_at.desc()))
        
        result = await session.exec(otp_statement)
        latest_otp_record = result.first()

        if not latest_otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail= "No OTP found"
            )
        
        if latest_otp_record.otp != otp_input.otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Invalid OTP code"
            )

        if datetime.now(timezone.utc) > latest_otp_record.expires:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP expired"
            )
        
        if otp_input.otp_type == OtpTypes.SIGNUP:
            user_statement = select(User).where(User.user_id == otp_input.user_id)
            result = await session.exec(user_statement)
            user = result.first()

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, 
                    detail="User not found"
                )
        
            try:
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
        
        if otp_input.otp_type == OtpTypes.FORGOTPASSWORD:
            try:
                await session.delete(latest_otp_record)
                await session.commit()
                return {"user_id": latest_otp_record.user_id}
            except DatabaseError:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error"
                )
            
    async def loginUser(self, loginInput: LoginInput, session:AsyncSession):
        statement = select(User).where(User.email == loginInput.email)
        result = await session.exec(statement)
        user = result.first()
        
        INVALID_CREDENTIALS = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Credentials"
        )

        if not user:
            raise INVALID_CREDENTIALS

        verified_password = verify_password_hash(loginInput.password, user.password_hash)
        if not verified_password:
            raise INVALID_CREDENTIALS

        user_dict = user.model_dump()
        access_token = create_token(user_dict, access_token_expiry, type="access")
        refresh_token = create_token(user_dict, refresh_token_expiry, type="refresh")

        user_details = {
            **user_dict, 
            'access_token': access_token,
            'refresh_token': refresh_token,
        }
        return user_details
    
    async def forgotPassword(self, forgotPasswordInput: ForgotPasswordInput, session: AsyncSession):
        statement = select(User).where(User.email == forgotPasswordInput.email)
        result = await session.exec(statement)
        user = result.first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail= "Email is not registered"
            ) 
        return user
    
    async def resetPassword(self, resetPasswordInput: ResetPasswordInput, session: AsyncSession):
        
        token_decode = decode_token(resetPasswordInput.token)
        
        if token_decode.get('type') != "reset":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

        user_id_from_token = token_decode.get('sub')
        statement = select(User).where(User.user_id == uuid.UUID(user_id_from_token))
        result = await session.exec(statement)
        user = result.first()

        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

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