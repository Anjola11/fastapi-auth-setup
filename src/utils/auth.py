import bcrypt
from datetime import datetime, timedelta, timezone
import jwt
import uuid
from src.config import Config
from fastapi import HTTPException, status


def generate_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password_hash(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_token(user_data: dict, expiry_delta: timedelta, type: str):
    current_time = datetime.now(timezone.utc)
    payload = {
        'iat': current_time,
        'jti': str(uuid.uuid4()),
        'sub': str(user_data.get('user_id')),
    }

    payload['exp'] = current_time + expiry_delta
    payload['type'] = type.lower()

    if type == "access":
        payload['email'] = user_data.get('email')

    token = jwt.encode(
        payload=payload,
        key=Config.JWT_KEY,
        algorithm=Config.JWT_ALGORITHM
    )
    return token

def decode_token(token: str) -> dict:
    try:

        token_data = jwt.decode(
            jwt=token,
            key=Config.JWT_KEY,
            algorithms=[Config.JWT_ALGORITHM],
            leeway=10
        )

    except jwt.InvalidTokenError:
    # Handles malformed tokens, wrong signatures, or tampered data
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token."
        )

    except Exception as e:
        # OPTIONAL: Catch unexpected system errors (like a code bug)
        print(f"Unexpected error: {e}") 
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Something went wrong processing the token."
        )
    return token_data