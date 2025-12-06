# FastAPI Authentication System Template

A robust, production-ready authentication backend template built with **FastAPI**, **SQLModel (PostgreSQL)**, and **Brevo** for email services. This system includes secure JWT authentication (Access + Refresh tokens), email verification via OTP, and password reset flows.

## 🚀 Features

* **User Registration:** Secure signup with password hashing (bcrypt).
* **Email Verification:** OTP-based email verification using Brevo (formerly Sendinblue).
* **JWT Authentication:** Secure Access and Refresh token implementation.
* **Password Management:** Forgot Password and Reset Password workflows with OTPs.
* **Async Database:** Fully asynchronous database operations using SQLModel and AsyncPG.
* **Scalable Structure:** Clean, modular architecture suitable for larger projects.

## 🛠️ Tech Stack

* **Framework:** FastAPI
* **Database:** PostgreSQL / SQLModel
* **Email Service:** Brevo (Transactional API)
* **Templating:** Jinja2 (for HTML emails)
* **Security:** PyJWT & Passlib/Bcrypt

---

## ⚙️ Setup & Installation

Follow these steps to set up the system for your own project.

### 1. Clone the Repository
Clone the template to your local machine (or use it as a base for your new repo).

```bash
git clone <your-repo-url> my-auth-project
cd my-auth-project
````

### 2\. Create a Virtual Environment

It is recommended to use a virtual environment to manage dependencies.

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3\. Install Dependencies

Install the required Python packages listed in `requirements.txt`.

```bash
pip install -r requirements.txt
```

### 4\. Database Setup

Ensure you have a PostgreSQL database running locally or in the cloud (e.g., Supabase, Neon, Render).

1.  Create a new database (e.g., `auth_db`).
2.  Get your connection string (DSN).

### 5\. Environment Configuration

Create a `.env` file in the root directory. This file will store your secrets and API keys.

**Create `.env`:**

```bash
touch .env
```

**Add the following content to `.env`:**

```ini
# --- Database Configuration ---
# Format: postgresql+asyncpg://<user>:<password>@<host>:<port>/<db_name>
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/auth_db

# --- Security ---
# Generate a strong random string (e.g., using `openssl rand -hex 32`)
JWT_KEY=your_super_secret_jwt_signing_key
JWT_ALGORITHM=HS256

# --- Email Service (Brevo) ---
# Get your API key from [https://app.brevo.com/settings/keys/api](https://app.brevo.com/settings/keys/api)
BREVO_API_KEY=xkeysib-your-brevo-api-key
BREVO_EMAIL=no-reply@yourdomain.com
BREVO_SENDER_NAME="Your App Auth"
```

### 6\. Run the Application

Start the FastAPI server using Uvicorn.

```bash
uvicorn src.__init__:app --reload
```

  * The server will start at `http://127.0.0.1:8000`.
  * The database tables will be created automatically on startup (via `src/db/main.py`).

-----

## 📖 How the System Works

### 1\. Registration Flow

  * User sends `POST /api/auth/signup` with name, email, and password.
  * System creates a user (inactive) and generates a **6-digit OTP**.
  * An email is sent to the user containing the OTP.

### 2\. Verification Flow

  * User sends `POST /api/auth/verify_otp` with the OTP received.
  * System validates the OTP. If correct, the user's account is marked as `verified`.
  * A "Welcome" email is sent to the user.

### 3\. Login Flow

  * User sends `POST /api/auth/login`.
  * System validates credentials.
  * **Response:** Returns an `access_token` (short-lived) and a `refresh_token` (long-lived).

### 4\. Password Reset

  * **Request:** `POST /api/auth/forgot_password` generates a secure OTP.
  * **Verify:** `POST /api/auth/verify_otp` (with type `forgotPassword`) verifies the code and returns a temporary **Reset Token**.
  * **Reset:** `PATCH /api/auth/reset_password` uses the Reset Token to set a new password.

-----

## 🔗 API Endpoints

Once the server is running, you can explore the interactive documentation at:
**Swagger UI:** `http://127.0.0.1:8000/docs`

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/signup` | Register a new user and send verification email. |
| `POST` | `/api/auth/verify_otp` | Verify email or password reset OTPs. |
| `POST` | `/api/auth/login` | Authenticate user and get JWT tokens. |
| `POST` | `/api/auth/forgot_password` | Request a password reset OTP. |
| `PATCH` | `/api/auth/reset_password` | Set a new password using a reset token. |
| `GET` | `/` | Health check. |

## 📂 Project Structure

```text
.
├── requirements.txt    # Project dependencies
├── .env                # Environment variables (do not commit this!)
└── src
    ├── auth            # Auth routes, models, and logic
    ├── db              # Database connection and session management
    ├── emailServices   # Brevo integration and email sending logic
    ├── templates       # HTML email templates (Jinja2)
    └── utils           # Helper functions (Hashing, OTPs, JWTs)
```

```
```