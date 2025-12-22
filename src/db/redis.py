from redis.asyncio import Redis
from src.config import Config

redis_client = Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    db=0,
    decode_responses=True
)

async def check_redis_connection():
    try:
        await redis_client.ping()
        print("Redis connection established")

    except Exception as e:
        print(f"Redis connection failed: {e}")


