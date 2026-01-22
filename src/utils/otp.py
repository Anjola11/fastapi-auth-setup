"""One-time password (OTP) utilities.

This module provides a secure OTP generator used for short-lived user
verification (for example, email or SMS verification codes). It uses the
`secrets` module to ensure cryptographic randomness suitable for
authentication contexts.
"""

import secrets
import string

def generate_otp(length: int = 6) -> str:
    
    # Generate cryptographically secure random digits
    otp = "".join(secrets.choice(string.digits) for _ in range(length))
    return otp