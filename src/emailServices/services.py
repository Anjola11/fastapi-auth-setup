from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.exc import DatabaseError
from fastapi import HTTPException, status
import uuid
from pathlib import Path
import brevo_python
from brevo_python.rest import ApiException
from jinja2 import Environment, FileSystemLoader
from src.config import Config
from src.auth.models import SignupOtp, ForgotPasswordOtp  
from src.emailServices.schemas import OtpTypes
from src.utils.otp import generate_otp

# Setup template directory paths
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR / "templates"

# Initialize Jinja2 template environment
template_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR)
)

class EmailServices:
    def __init__(self):
        self.BREVO_API_KEY = Config.BREVO_API_KEY
        self.BREVO_EMAIL = Config.BREVO_EMAIL
        self.BREVO_SENDER_NAME = Config.BREVO_SENDER_NAME

        self.configuration = brevo_python.Configuration()
        self.configuration.api_key['api-key'] = self.BREVO_API_KEY
        self.api_instance = brevo_python.TransactionalEmailsApi(brevo_python.ApiClient(self.configuration))

    async def save_otp(self, user_id: uuid.UUID, session: AsyncSession, type: OtpTypes):
        if type == OtpTypes.SIGNUP:
            model = SignupOtp
        elif type == OtpTypes.FORGOTPASSWORD:
            model = ForgotPasswordOtp
            
        new_otp = model(
            otp=generate_otp(),
            user_id=user_id
        )

        try:
            session.add(new_otp)
            await session.commit()
            await session.refresh(new_otp)
            return new_otp
        except DatabaseError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
        
    def render_template(self, template_name: str, payload: dict = {}):
        try:
            template = template_env.get_template(f"{template_name}.html")
            return template.render(**payload)
        except Exception as err:
            print(f"Error rendering template '{template_name}': {err}")
            raise err
    
    def send_email(self, to_email: str, subject: str, html_content: str, text_content: str) -> bool:
        if not self.BREVO_API_KEY:
            print(f"Brevo API key not configured. Skipping email to: {to_email}")
            return False

        sender = {"name": self.BREVO_SENDER_NAME, "email": self.BREVO_EMAIL}
        to = [{"email": to_email}]

        send_smtp_email = brevo_python.SendSmtpEmail(
            to=to,
            sender=sender,
            subject=subject,
            html_content=html_content,
            text_content=text_content
        )

        try:
            self.api_instance.send_transac_email(send_smtp_email)
            print(f"Email sent to {to_email}: {subject}")
            return True
        except ApiException as e:
            print(f"Error sending email: {e}")
            return False
    
    def send_email_verification_otp(self, user_email: str, otp_code: str, user_name: str):
        html = self.render_template('email-otp-verification', {
            'username': user_name,
            'otpCode': otp_code,
            'expiryTime': '10 minutes'
        })

        text_content = f"Hello {user_name}, Your verification code is: {otp_code}"
        return self.send_email(user_email, 'Verify your email', html, text_content)

    def send_welcome_email(self, user_email: str, user_name: str):
        html = self.render_template('welcome', {
            'username': user_name,
            'email': user_email 
        })
        text_content = f"Welcome, {user_name}! Thank you for verifying your email."
        return self.send_email(user_email, 'Welcome!', html, text_content)
    
    def send_forgot_password_otp(self, user_email: str, otp_code: str, user_name: str):
        html = self.render_template('forgot-password-otp', {
            'username': user_name,
            'otpCode': otp_code,
            'expiryTime': '5 minutes'
        })
        text_content = f"Hello {user_name}, Your Password Reset Code is: {otp_code}"
        return self.send_email(user_email, 'Reset your password', html, text_content)