"""Query functions. Table classes and the engine live in db.py; request/response
shapes live in models.py. Every function opens its own short-lived session and
returns Pydantic models, never ORM rows."""

import argparse
import asyncio
import os
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import contains_eager, selectinload

import config
import db
import models

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "backups")

MEAL_FIELDS = tuple(f"d{day}_{meal}" for day in (1, 2, 3) for meal in ("bf", "lunch", "hitea"))


####################
# ROW <-> MODEL MAPPING
####################


def _experience_rows(experiences: list[models.MunExperience]) -> list[db.MunExperienceRow]:
    return [
        db.MunExperienceRow(
            position=position,
            name=mun.name,
            committee=mun.committee,
            delegation=mun.delegation,
            year=mun.year,
            award=mun.award,
        )
        for position, mun in enumerate(experiences)
    ]


def _delegate_fields(row: db.DelegateRow) -> dict:
    """Needs row.experiences loaded."""
    return dict(
        id=row.id,
        firstname=row.firstname,
        lastname=row.lastname,
        email=row.email,
        contact=row.contact,
        dateofbirth=row.dateofbirth,
        gender=row.gender,
        pastmuns=[
            models.MunExperience(
                name=e.name,
                committee=e.committee,
                delegation=e.delegation,
                year=e.year,
                award=e.award,
            )
            for e in row.experiences
        ],
        verified=row.verified,
    )


def _to_delegate(row: db.DelegateRow) -> models.Delegate:
    return models.Delegate(**_delegate_fields(row))


def _to_mm_delegate(row: db.DelegateRow) -> models.MMDelegate:
    """Needs row.experiences and row.mm loaded."""
    mm = row.mm
    return models.MMDelegate(
        **_delegate_fields(row),
        country=mm.country,
        committee=mm.committee,
        **{field: getattr(mm, field) for field in MEAL_FIELDS},
    )


def _apply_delegate(row: db.DelegateRow, delegate: models.Delegate) -> None:
    row.firstname = delegate.firstname
    row.lastname = delegate.lastname
    row.email = delegate.email
    row.contact = delegate.contact
    row.dateofbirth = delegate.dateofbirth
    row.gender = delegate.gender
    row.verified = delegate.verified


_WITH_EXPERIENCES = selectinload(db.DelegateRow.experiences)


####################
# USERS
####################


async def add_user(user: models.User) -> models.User:
    async with db.SessionLocal() as session, session.begin():
        session.add(db.UserRow(email=user.email, password=user.password))
    return user


async def get_user_by_email(email: str) -> models.User | None:
    async with db.SessionLocal() as session:
        result = await session.execute(
            select(db.UserRow.password, db.DelegateRow)
            .join(db.DelegateRow, db.DelegateRow.email == db.UserRow.email)
            .where(db.UserRow.email == email)
            .options(selectinload(db.DelegateRow.experiences))
        )
        found = result.first()
        if found is None:
            return None
        password, delegate = found
        return models.User(
            firstname=delegate.firstname,
            lastname=delegate.lastname,
            email=delegate.email,
            password=password,
        )


async def get_role(email: str) -> models.Role | None:
    async with db.SessionLocal() as session:
        return await session.scalar(select(db.UserRow.role).where(db.UserRow.email == email))


async def get_auth_user(email: str) -> models.AuthUser | None:
    """The delegate profile and role of the user with this email, or None if there is
    no such user. Called on every authenticated request."""
    async with db.SessionLocal() as session:
        result = await session.execute(
            select(db.DelegateRow, db.UserRow.role)
            .join(db.UserRow, db.UserRow.email == db.DelegateRow.email)
            .where(db.DelegateRow.email == email)
            .options(_WITH_EXPERIENCES)
        )
        found = result.first()
        if found is None:
            return None
        delegate, role = found
        return models.AuthUser(**_delegate_fields(delegate), role=role)


async def change_user_pass(email: models.EmailStr, password: str) -> None:
    async with db.SessionLocal() as session, session.begin():
        await session.execute(
            update(db.UserRow).where(db.UserRow.email == email).values(password=password)
        )


async def delete_user(email: models.EmailStr) -> None:
    async with db.SessionLocal() as session, session.begin():
        user = await session.get(db.UserRow, email)
        if user is not None:
            await session.delete(user)


####################
# ROLES
####################


async def set_role(actor_email: str, target_email: str, new_role: str) -> str:
    """Change target's role and record it in the audit table. Returns the old role.

    Raises ValueError (unknown role), PermissionError (actor is not an admin, is
    changing their own role, or this would remove the last admin) or LookupError
    (no such user).
    """
    if new_role not in db.ROLES:
        raise ValueError(f"Unknown role: {new_role}")
    if actor_email == target_email:
        raise PermissionError("You cannot change your own role")

    async with db.SessionLocal() as session, session.begin():
        # Lock every admin row (in a fixed order, so concurrent calls cannot deadlock)
        # and re-check the actor inside the transaction: two admins demoting each
        # other at the same moment must not leave the system with zero admins.
        admins = (
            await session.scalars(
                select(db.UserRow.email)
                .where(db.UserRow.role == "admin")
                .order_by(db.UserRow.email)
                .with_for_update()
            )
        ).all()
        if actor_email not in admins:
            raise PermissionError("Only admins can change roles")

        target = await session.get(db.UserRow, target_email, with_for_update=True)
        if target is None:
            raise LookupError("User not found")
        if target.role == "admin" and new_role != "admin" and len(admins) <= 1:
            raise PermissionError("You cannot demote the last admin")

        old_role = target.role
        if old_role != new_role:
            target.role = new_role
            session.add(
                db.AdminAuditRow(
                    actor_email=actor_email,
                    target_email=target_email,
                    old_role=old_role,
                    new_role=new_role,
                )
            )
        return old_role


async def make_admin(email: str) -> str:
    """Bootstrap path for the first admin, used by the command line below. Returns the
    old role. Raises LookupError if there is no user with this email."""
    async with db.SessionLocal() as session, session.begin():
        user = await session.get(db.UserRow, email, with_for_update=True)
        if user is None:
            raise LookupError(f"No user with email {email}. Register the account first.")
        old_role = user.role
        if old_role != "admin":
            user.role = "admin"
            session.add(
                db.AdminAuditRow(
                    actor_email="system:cli",
                    target_email=email,
                    old_role=old_role,
                    new_role="admin",
                )
            )
        return old_role


####################
# DELEGATES
####################


async def add_delegate(delegate: models.Delegate) -> models.Delegate:
    row = db.DelegateRow(
        id=delegate.id,
        firstname=delegate.firstname,
        lastname=delegate.lastname,
        email=delegate.email,
        contact=delegate.contact,
        dateofbirth=delegate.dateofbirth,
        gender=delegate.gender,
        verified=delegate.verified,
        experiences=_experience_rows(delegate.pastmuns),
    )
    async with db.SessionLocal() as session, session.begin():
        session.add(row)
    return delegate


async def get_delegates() -> list[models.Delegate]:
    async with db.SessionLocal() as session:
        rows = await session.scalars(
            select(db.DelegateRow)
            .options(_WITH_EXPERIENCES)
            .order_by(db.DelegateRow.created_at, db.DelegateRow.id)
        )
        return [_to_delegate(row) for row in rows]


async def get_delegate_by_id(id: str) -> models.Delegate | None:
    async with db.SessionLocal() as session:
        row = await session.scalar(
            select(db.DelegateRow).where(db.DelegateRow.id == id).options(_WITH_EXPERIENCES)
        )
        return _to_delegate(row) if row else None


async def get_delegate_by_email(email: models.EmailStr) -> models.Delegate | None:
    async with db.SessionLocal() as session:
        row = await session.scalar(
            select(db.DelegateRow)
            .where(db.DelegateRow.email == email)
            .options(_WITH_EXPERIENCES)
        )
        return _to_delegate(row) if row else None


async def update_delegate_by_id(id: str, delegate: models.Delegate) -> models.Delegate:
    async with db.SessionLocal() as session, session.begin():
        row = await session.scalar(
            select(db.DelegateRow).where(db.DelegateRow.id == id).options(_WITH_EXPERIENCES)
        )
        if row is not None:
            _apply_delegate(row, delegate)
            row.experiences = _experience_rows(delegate.pastmuns)
    return delegate


async def verify_delegate_email(email: models.EmailStr) -> None:
    async with db.SessionLocal() as session, session.begin():
        await session.execute(
            update(db.DelegateRow).where(db.DelegateRow.email == email).values(verified=True)
        )


####################
# MM DELEGATES
####################
# An MM delegate is a delegate (same id) plus a mm_delegates row. The profile fields
# live only in delegates; the mm_delegates row holds country, committee and meals.


def _mm_query():
    return (
        select(db.DelegateRow)
        .join(db.DelegateRow.mm)
        .options(contains_eager(db.DelegateRow.mm), _WITH_EXPERIENCES)
    )


async def add_mm_delegate(mm_delegate: models.MMDelegate) -> models.MMDelegate:
    """The delegate with this id must already exist."""
    async with db.SessionLocal() as session, session.begin():
        session.add(
            db.MMDelegateRow(
                delegate_id=mm_delegate.id,
                country=mm_delegate.country,
                committee=mm_delegate.committee,
                **{field: getattr(mm_delegate, field) for field in MEAL_FIELDS},
            )
        )
    return mm_delegate


async def get_mm_delegates() -> list[models.MMDelegate]:
    async with db.SessionLocal() as session:
        rows = await session.scalars(
            _mm_query().order_by(db.DelegateRow.created_at, db.DelegateRow.id)
        )
        return [_to_mm_delegate(row) for row in rows]


async def get_mm_delegate_by_id(id: str) -> models.MMDelegate | None:
    async with db.SessionLocal() as session:
        row = await session.scalar(_mm_query().where(db.DelegateRow.id == id))
        return _to_mm_delegate(row) if row else None


async def get_mm_delegate_by_email(email: str) -> models.MMDelegate | None:
    async with db.SessionLocal() as session:
        row = await session.scalar(_mm_query().where(db.DelegateRow.email == email))
        return _to_mm_delegate(row) if row else None


async def update_mm_delegate(id: str, mm_delegate: models.MMDelegate) -> models.MMDelegate:
    """Updates only the Mumbai MUN fields (country, committee, meals). Profile fields
    are changed through update_delegate_by_id."""
    async with db.SessionLocal() as session, session.begin():
        row = await session.get(db.MMDelegateRow, id)
        if row is not None:
            row.country = mm_delegate.country
            row.committee = mm_delegate.committee
            for field in MEAL_FIELDS:
                setattr(row, field, getattr(mm_delegate, field))
    return mm_delegate


async def delete_mm_delegate(id: str) -> None:
    """Removes the Mumbai MUN registration; the delegate profile stays."""
    async with db.SessionLocal() as session, session.begin():
        row = await session.get(db.MMDelegateRow, id)
        if row is not None:
            await session.delete(row)


####################
# BACKUP
####################


async def backup_database() -> str:
    """Runs pg_dump (custom format, already compressed; restore with pg_restore) into
    BACKUP_DIR and returns the file path. Needs pg_dump 16 or newer on PATH."""
    settings = config.get_settings()
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(BACKUP_DIR, f"mundra-ondemand-{stamp}.dump")

    process = await asyncio.create_subprocess_exec(
        "pg_dump",
        "--format=custom",
        "--file", path,
        "--host", settings.postgres_host,
        "--port", str(settings.postgres_port),
        "--username", settings.postgres_user,
        "--dbname", settings.postgres_db,
        # The password goes in the environment, not argv, so it is not visible in `ps`.
        env={**os.environ, "PGPASSWORD": settings.postgres_password},
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {stderr.decode().strip()}")
    return path


####################
# COMMAND LINE
####################


async def _cli(args: argparse.Namespace) -> int:
    try:
        if args.command == "make-admin":
            old_role = await make_admin(args.email)
            if old_role == "admin":
                print(f"{args.email} is already an admin.")
            else:
                print(f"{args.email}: {old_role} -> admin")
        return 0
    except LookupError as e:
        print(e)
        return 1
    finally:
        await db.engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MUNDRA database commands")
    commands = parser.add_subparsers(dest="command", required=True)
    make_admin_parser = commands.add_parser(
        "make-admin", help="Give an existing user the admin role (first-admin bootstrap)"
    )
    make_admin_parser.add_argument("email")
    raise SystemExit(asyncio.run(_cli(parser.parse_args())))
