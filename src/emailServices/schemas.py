from enum import Enum

class OtpTypes(str, Enum):
    SIGNUP = "signup"
    FORGOTPASSWORD = "forgotPassword"