"""Shared test helpers. Each test uses fresh, unique data instead of clearing tables,
because some fixtures (admin, mm_delegate) live for the whole session."""

import uuid

from sqlalchemy import update

import auth
import database
import db
import models


def unique_email() -> str:
    return f"{uuid.uuid4().hex[:12]}@example.com"


async def create_user(
    email: str | None = None,
    password: str = "password-123",
    role: str = "delegate",
    verified: bool = True,
) -> str:
    """Register a delegate and their login, then give them the role. Returns the email."""
    email = email or unique_email()
    await database.add_delegate(
        models.Delegate(
            id=uuid.uuid4().hex,
            firstname="Test",
            lastname="User",
            email=email,
            verified=verified,
        )
    )
    await database.add_user(
        models.User(
            firstname="Test",
            lastname="User",
            email=email,
            password=auth.hash_password(password),
        )
    )
    if role == "admin":
        await database.make_admin(email)
    elif role != "delegate":
        # 'oc' has no bootstrap command; set it the way the admin route would.
        async with db.SessionLocal() as session, session.begin():
            await session.execute(
                update(db.UserRow).where(db.UserRow.email == email).values(role=role)
            )
    return email


def auth_header(email: str) -> dict[str, str]:
    """A bearer header for this user, minted directly so tests don't hit the
    rate-limited /login route."""
    token = auth.create_access_token({"sub": email})
    return {"Authorization": f"Bearer {token}"}
