from sqlalchemy.ext.asyncio import create_async_engine
from src.config import Config
from sqlmodel import SQLModel
from sqlalchemy.orm import sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

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