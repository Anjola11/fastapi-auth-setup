import secrets
import string

def generate_otp(length: int = 6) -> str:
    """Generate cryptographically secure random digits."""
    otp = "".join(secrets.choice(string.digits) for _ in range(length))
    return otp