from fastapi import FastAPI, HTTPException, Request, status
from contextlib import asynccontextmanager
from src.db.main import init_db
from src.db.redis import redis_client, check_redis_connection
from src.auth.routes import authRouter
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n---Server Started---\n")
    
    # 1. Initialize Postgres
    await init_db()
    
    # 2. Check Redis Connection
    await check_redis_connection()
    
    yield
    
    # 3. Clean up Redis connections on shutdown
    print("---Closing Redis Connection---")
    await redis_client.close()
    print("---Server Closed---")

app = FastAPI(
    title="Template API",
    description="Auth Template",
    lifespan = lifespan
)

@app.get("/")
def health_check():
    return{
        "status": "Success",
        "message": "Server Working"
    }

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "data": None
        }
    )

def format_validation_errors(errors):
    formatted = []
    for err in errors:
        field = ".".join(str(loc) for loc in err["loc"][1:])
        formatted.append({
            "field": field,
            "message": err["msg"]
        })
    return formatted

@app.exception_handler(RequestValidationError)
async def custom_validation_exception_handler(request:Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "success": False,
            "message": "Validation error",
            "errors": format_validation_errors(exc.errors()),
            "data": None
        }
    )

app.include_router(authRouter, prefix="/api/auth")