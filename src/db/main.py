from sqlalchemy.ext.asyncio import create_async_engine
from src.config import Config
from sqlmodel import SQLModel
from sqlalchemy.orm import sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession
from src.auth.models import User, SignupOtp, ForgotPasswordOtp
from sqlmodel import select
from datetime import datetime, timezone, timedelta

engine = create_async_engine(
    url=Config.DATABASE_URL,
    echo=False, # Set to True for debugging
)

async def init_db():
    async with engine.begin() as conn:
        # Import models here to ensure they are registered
        from src.auth.models import User, SignupOtp, ForgotPasswordOtp
        await conn.run_sync(SQLModel.metadata.create_all)

# Session factory configured for async operations
async_session_maker = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_Session():
    async with async_session_maker() as session:
        yield session


class DbCleanupServices:
    datetime_now = datetime.now(timezone.utc)
    unregisted_user_limit = timedelta(days=1)
    async def users_cleanup(self):
        async with async_session_maker() as session:
            
            try:
                statement = select(User).where(User.email_verified == False, User.created_at + self.unregisted_user_limit < self.datetime_now)
                result = await session.exec(statement)
                unverified_users = result.all()

                for user in unverified_users:
                    await session.delete(user)
                await session.commit()
                print("daily cleanup done")
        
            except Exception as e:
                await session.rollback()
                print(f" Cleanup Failed: {e}")

    async def universal_otp_cleanup(self):

        models = [SignupOtp, ForgotPasswordOtp]
        async with async_session_maker() as session:

            for model in models:
                try:
                    statement = select(model).where(model.expires <= self.datetime_now)
                    result = await session.exec(statement)
                    expired_signup_otp= result.all()

                    for otp in expired_signup_otp:
                        await session.delete(otp)
                    await session.commit()
                    print(f"daily {getattr(model, '__tablename__', 'user').lower()} cleanup done")
                
                except Exception as e:
                    await session.rollback()
                    print(f" Cleanup Failed: {e}")

