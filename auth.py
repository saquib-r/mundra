import jwt, bcrypt, string, secrets, os
from datetime import datetime, timedelta, timezone
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import config, models, database

settings = config.get_settings()

SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
VERIFICATION_TOKEN_EXPIRE_MINUTES = settings.verification_token_expire_minutes

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> models.AuthUser:
    credentials_exception = HTTPException(
        status_code=403,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    # The role is read from the database on every request, not from the token, so a
    # demotion or a deleted account takes effect immediately.
    user = await database.get_auth_user(email)
    if not user:
        raise credentials_exception
    if not user.verified:
        raise HTTPException(status_code=401, detail="Please verify your email!")
    return user


def require_role(*roles: str):
    """Dependency that only lets users with one of the given roles through."""

    async def dependency(user: models.AuthUser = Depends(get_current_user)) -> models.AuthUser:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dependency


require_admin = require_role("admin")

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_verification_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

async def check_verification_token(token: str = Depends(oauth2_scheme)) -> models.Delegate:
    credentials_exception = HTTPException(
        status_code=403,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Verification token expired")
    except InvalidTokenError:
        raise credentials_exception
    delegate = await database.get_delegate_by_email(email)
    if not delegate:
        raise credentials_exception
    return delegate

def generate_password(length: int = 10) -> str:
    characters = string.ascii_letters.replace('l', '').replace('I', '') + string.digits.replace('1', '') + '!@#$%^&*()_+=-'
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password
