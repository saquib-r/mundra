import asyncio
import csv
from contextlib import asynccontextmanager
from functools import lru_cache
from io import StringIO
import os
from typing import Annotated
import uuid
import json

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from auth import (
    check_verification_token,
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
import config
import database
import db
import mails
import models
import utils

####################

# Initialization

limiter = Limiter(key_func=get_remote_address)

settings = config.get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await db.engine.dispose()


app = FastAPI(
    lifespan=lifespan,
    title="MUNDRA - MUNSoc Delegate Resource Application",
    description="Named after Mundra Port, Kutch, Gujarat, MUNDRA - MUNSoc Delegate Resource Application is a centralized database designed to optimize event planning, streamline communication, and facilitate delegate management",
    version="1.0.0",
    docs_url=settings.docs_url,
    redoc_url=settings.redoc_url,
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/", tags=["Status"])
def status():
    return {"message": "Server is up and running"}


####################

# Auth


@app.post(
    "/register",
    tags=["Auth"],
    status_code=201,
    responses={
        429: {"model": models.ErrorResponse},
        409: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
@limiter.limit("10/minute")
async def register(request: Request, user: models.User):
    try:
        user.password = await asyncio.to_thread(hash_password, user.password)

        user_exists = await database.get_user_by_email(user.email)
        if user_exists:
            raise HTTPException(status_code=409, detail="User already exists")

        delegate = await database.get_delegate_by_email(user.email)
        if not delegate:
            uid = str(uuid.uuid4()).replace("-", "")
            delegate = await database.add_delegate(
                models.Delegate(
                    id=uid,
                    firstname=user.firstname,
                    lastname=user.lastname,
                    email=user.email,
                )
            )
        await database.add_user(user)

        try:
            await mails.send_verification_email(delegate)
            return JSONResponse(
                status_code=201,
                content={
                    "message": "User created successfully. Please verify your email."
                },
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/login",
    tags=["Auth"],
    response_model=models.Token,
    responses={
        401: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
@limiter.limit("10/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username
    password = form_data.password

    user = await database.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email")
    if not await asyncio.to_thread(verify_password, password, user.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # user_type keeps the two values the app already understands; "oc" reports as "user".
    user_type = "admin" if await database.get_role(user.email) == "admin" else "user"
    access_token = create_access_token(data={"sub": user.email, "type": user_type})
    return models.Token(access_token=access_token, token_type="bearer", user_type=user_type)


@app.get(
    "/verify_email",
    tags=["Auth"],
    status_code=200,
    responses={500: {"model": models.ErrorResponse}},
)
@limiter.limit("10/minute")
async def verify_email(request: Request, token: str):
    try:
        delegate = await check_verification_token(token)
        if type(delegate) != models.Delegate:
            raise HTTPException(status_code=401, detail="Invalid token")
        await database.verify_delegate_email(delegate.email)
        return JSONResponse(status_code=200, content={"message": "Email verified!"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/resend_verification",
    tags=["Auth"],
    responses={
        404: {"model": models.ErrorResponse},
        409: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
@limiter.limit("10/minute")
async def resend_verification_email(request: Request, email: models.EmailStr):
    try:
        delegate = await database.get_delegate_by_email(email)
        if not delegate:
            raise HTTPException(status_code=404, detail="Delegate not found")
        if delegate.verified:
            raise HTTPException(status_code=409, detail="Email already verified")
        await mails.send_verification_email(delegate)
        return JSONResponse(
            status_code=200, content={"message": "Verification email sent!"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/forgot_password",
    tags=["Auth"],
    status_code=200,
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
@limiter.limit("1/minute")
async def forgot_password(request: Request, email: models.EmailStr):
    try:
        delegate = await database.get_delegate_by_email(email)
        if not delegate:
            raise HTTPException(status_code=404, detail="User not found")
        if not delegate.verified:
            raise HTTPException(status_code=403, detail="User not verified")
        access_token = create_access_token(data={"sub": delegate.email})
        link = f"{settings.url}/reset?token={access_token}"
        await mails.send_password_reset_email(delegate, link)
        return JSONResponse(
            status_code=200, content={"message": "Password reset email sent!"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch(
    "/change_pass",
    tags=["Auth"],
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
@limiter.limit("1/minute")
async def change_password(
    request: Request,
    password: str,
    delegate: models.AuthUser = Depends(get_current_user),
):
    try:
        user = await database.get_user_by_email(delegate.email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        await database.change_user_pass(
            user.email, await asyncio.to_thread(hash_password, password)
        )
        return JSONResponse(status_code=200, content={"message": "Password changed!"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


####################

# ADMIN STUFF


@app.get(
    "/hash_password", tags=["Admin"], responses={500: {"model": models.ErrorResponse}}
)
def get_hashed_password(password: str) -> str:
    try:
        return hash_password(password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/backup",
    tags=["Admin"],
    response_class=FileResponse,
    responses={
        403: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def backup_database(user: models.AuthUser = Depends(require_admin)):
    """Runs pg_dump now and returns the dump (restore it with pg_restore)."""
    try:
        path = await database.backup_database()
        return FileResponse(
            path, media_type="application/octet-stream", filename=os.path.basename(path)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch(
    "/admin/users/{email}/role",
    tags=["Admin"],
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
    },
)
async def change_role(
    email: models.EmailStr,
    change: models.RoleChange,
    admin: models.AuthUser = Depends(require_admin),
):
    """Give a user the delegate, oc or admin role. Every change is written to the
    admin_audit table."""
    try:
        old_role = await database.set_role(admin.email, email, change.role)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return {"email": email, "old_role": old_role, "new_role": change.role}


@app.get(
    "/delegates",
    tags=["Admin"],
    response_model=list[models.Delegate],
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def get_delegates(token: str = "", format: str = ""):
    try:
        user = await get_current_user(token)
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        data = await database.get_delegates()
        if data:
            if format == "csv":
                output = StringIO()
                writer = csv.writer(output)
                writer.writerow(
                    [
                        "id",
                        "firstname",
                        "lastname",
                        "email",
                        "contact",
                        "dateofbirth",
                        "gender",
                        "pastmuns",
                    ]
                )

                for delegate in data:
                    past_muns_info = []
                    for mun in delegate.pastmuns:
                        past_muns_info.append(
                            f"{mun.name} | {mun.committee} | {mun.delegation} | {mun.year} | {mun.award}"
                        )

                    writer.writerow(
                        [
                            delegate.id,
                            delegate.firstname,
                            delegate.lastname,
                            delegate.email,
                            delegate.contact,
                            delegate.dateofbirth,
                            delegate.gender,
                            " ; ".join(past_muns_info),
                        ]
                    )

                csv_data = output.getvalue()
                output.close()

                return Response(content=csv_data, media_type="text/csv")
            return data
        raise HTTPException(status_code=404, detail="No delegates found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


####################

# DELEGATE STUFF


@app.get(
    "/delegates/me",
    tags=["Delegates"],
    response_model=models.Delegate,
    responses={500: {"model": models.ErrorResponse}},
)
def get_current_delegate(user: models.AuthUser = Depends(get_current_user)):
    return user


@app.get(
    "/delegates/{id}",
    tags=["Delegates"],
    response_model=models.Delegate,
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def get_delegate_by_id(
    id: str, user: models.AuthUser = Depends(get_current_user)
):
    try:
        if user.role != "admin":
            if user.id == id:
                return user
            raise HTTPException(status_code=403, detail="Forbidden")
        data = await database.get_delegate_by_id(id)
        if data:
            return data
        raise HTTPException(status_code=404, detail="Delegate not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch(
    "/delegates/{id}",
    tags=["Delegates"],
    response_model=models.Delegate,
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def update_delegate(
    id: str,
    user: models.AuthUser = Depends(get_current_user),
    firstname: str = "",
    lastname: str = "",
    contact: str = "",
    dateofbirth: str = "",
    gender: str = "",
    pastmuns: list[models.MunExperience] = [],
    verified: bool = False,
):
    try:
        if user.role != "admin" and user.id != id:
            raise HTTPException(status_code=403, detail="Forbidden")
        data = await database.get_delegate_by_id(id)
        if not data:
            raise HTTPException(status_code=404, detail="Delegate not found")
        if firstname != "":
            data.firstname = firstname
        if lastname != "":
            data.lastname = lastname
        if contact != "":
            data.contact = contact
        if dateofbirth != "":
            data.dateofbirth = dateofbirth
        if gender != "":
            data.gender = gender
        if pastmuns != []:
            data.pastmuns = pastmuns
        if verified:
            data.verified = verified
        return await database.update_delegate_by_id(id, data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


####################

# MUMBAIMUN QR CODES


@app.get("/qr", tags=["QR"])
def get_qr(id: str):
    try:
        qr_folder = utils.qr_folder
        if not os.path.exists(qr_folder):
            os.makedirs(qr_folder)

        qr_image = f"{qr_folder}/{id}.jpg"

        if not os.path.exists(qr_image):
            utils.generate_qr(id)
        try:
            return FileResponse(qr_image)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# REGISTER STUFF

mm_router = APIRouter(prefix="/mumbaimun", tags=["Mumbai MUN"])


@mm_router.post(
    "/register",
    tags=["Auth"],
    status_code=201,
    responses={
        400: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def mm_register(request: Request, user: models.User):
    try:
        user.password = await asyncio.to_thread(hash_password, user.password)
        user_exists = await database.get_user_by_email(user.email)

        if user_exists:
            delegate = await database.get_delegate_by_email(user.email)

            if not delegate:
                raise HTTPException(
                    status_code=400, detail="User exists but is not a delegate."
                )
            if not delegate.verified:
                delegate.verified = True
                await database.update_delegate_by_id(delegate.id, delegate)

            mm_delegate = await database.get_mm_delegate_by_email(user.email)

            if mm_delegate:
                raise HTTPException(
                    status_code=409,
                    detail=f"Mumbai MUN Delegate already registered! ID: {mm_delegate.id}",
                )

            mm_delegate = await database.add_mm_delegate(
                models.MMDelegate(
                    id=delegate.id,
                    firstname=delegate.firstname,
                    lastname=delegate.lastname,
                    email=delegate.email,
                    contact=delegate.contact,
                    dateofbirth=delegate.dateofbirth,
                    gender=delegate.gender,
                    pastmuns=delegate.pastmuns,
                    verified=delegate.verified,
                )
            )

            return JSONResponse(
                status_code=201,
                content={
                    "message": f"Mumbai MUN Delegate registered successfully! ID: {mm_delegate.id}"
                },
            )

        else:

            delegate = await database.get_delegate_by_email(user.email)
            if not delegate:
                uid = str(uuid.uuid4()).replace("-", "")
                delegate = await database.add_delegate(
                    models.Delegate(
                        id=uid,
                        firstname=user.firstname,
                        lastname=user.lastname,
                        email=user.email,
                        verified=True,
                    )
                )

            await database.add_user(user)

            if not delegate.verified:
                delegate.verified = True
                await database.update_delegate_by_id(delegate.id, delegate)

            mm_delegate = await database.add_mm_delegate(
                models.MMDelegate(
                    id=delegate.id,
                    firstname=delegate.firstname,
                    lastname=delegate.lastname,
                    email=delegate.email,
                    contact=delegate.contact,
                    dateofbirth=delegate.dateofbirth,
                    gender=delegate.gender,
                    pastmuns=delegate.pastmuns,
                    verified=delegate.verified,
                )
            )

            try:
                await mails.send_verification_email(delegate)
                return JSONResponse(
                    status_code=201,
                    content={
                        "message": f"User with id {delegate.id} created successfully!"
                    },
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@mm_router.get(
    "/delegates",
    tags=["Admin"],
    response_model=list[models.MMDelegate],
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def get_mm_delegates(
    user: models.AuthUser = Depends(require_admin), format: str = ""
):
    try:
        data = await database.get_mm_delegates()
        if data:
            if format == "csv":
                output = StringIO()
                writer = csv.writer(output)
                writer.writerow(
                    [
                        "id",
                        "firstname",
                        "lastname",
                        "email",
                        "contact",
                        "dateofbirth",
                        "gender",
                        "pastmuns",
                    ]
                )

                for delegate in data:
                    past_muns_info = []
                    for mun in delegate.pastmuns:
                        past_muns_info.append(
                            f"{mun.name} | {mun.committee} | {mun.delegation} | {mun.year} | {mun.award}"
                        )

                    writer.writerow(
                        [
                            delegate.id,
                            delegate.firstname,
                            delegate.lastname,
                            delegate.email,
                            delegate.contact,
                            delegate.dateofbirth,
                            delegate.gender,
                            " ; ".join(past_muns_info),
                        ]
                    )

                csv_data = output.getvalue()
                output.close()

                return Response(content=csv_data, media_type="text/csv")
            return data
        raise HTTPException(status_code=404, detail="No delegates found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


app.include_router(mm_router)

#####################################
# Changes related to food by Kartik #
#####################################


@app.get("/scan", tags=["QR"])
def scan(request: Request):
    return templates.TemplateResponse(request, "scan.html")


@app.get("/food", tags=["Food"], response_class=HTMLResponse)
async def get_food(request: Request, id: str):
    try:
        delegate = await database.get_mm_delegate_by_id(id)
        if not delegate:
            raise HTTPException(status_code=404, detail="Delegate not found")

        return templates.TemplateResponse(
            request, "food.html", {"delegate": delegate}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Literally anyone in the wild can update this which is concerning, Will fix this later
@app.post("/food", tags=["Food"], status_code=201)
async def update_food(
    id: Annotated[str, Form()],
    d1_bf: Annotated[bool, Form()] = True,
    d1_lunch: Annotated[bool, Form()] = False,
    d1_hitea: Annotated[bool, Form()] = False,
    d2_bf: Annotated[bool, Form()] = False,
    d2_lunch: Annotated[bool, Form()] = False,
    d2_hitea: Annotated[bool, Form()] = False,
    d3_bf: Annotated[bool, Form()] = False,
    d3_lunch: Annotated[bool, Form()] = False,
    d3_hitea: Annotated[bool, Form()] = False,
):
    # Fetch the existing delegate
    delegate = await database.get_mm_delegate_by_id(id)
    if not delegate:
        raise HTTPException(status_code=404, detail="Delegate not found")

    delegate.d1_bf = d1_bf
    delegate.d1_lunch = d1_lunch
    delegate.d1_hitea = d1_hitea
    delegate.d2_bf = d2_bf
    delegate.d2_lunch = d2_lunch
    delegate.d2_hitea = d2_hitea
    delegate.d3_bf = d3_bf
    delegate.d3_lunch = d3_lunch
    delegate.d3_hitea = d3_hitea

    try:
        await database.update_mm_delegate(delegate.id, delegate)
        return JSONResponse(
            status_code=201,
            content={"message": "Food updated successfully"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#####################################
# OC STUFF
#####################################

# again, anyone in the wild can bypass email verification, will fix later
@app.post("/manual_verify", tags=["OC"], status_code=201)
async def manual_verify(email: str):
    try:
        delegate = await database.get_delegate_by_email(email)
        if not delegate:
            raise HTTPException(status_code=404, detail="Delegate not found")

        delegate.verified = True
        await database.update_delegate_by_id(delegate.id, delegate)

        return JSONResponse(status_code=201, content={"message": "Email verified!"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#####################################
# DELETE USER ACCOUNT
#####################################


@app.delete("/account", tags=["Auth"], status_code=200)
async def delete_user(user: models.AuthUser = Depends(get_current_user)):
    if user.role == "admin":
        raise HTTPException(
            status_code=403,
            detail="Admins must be demoted before they can delete their account",
        )
    try:
        await database.delete_user(user.email)
        return JSONResponse(
            status_code=200, content={"message": "Account deleted successfully"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


###############################################
# Changes Regarding Password Changes By Kartik
###############################################

@app.get(
    "/reset",
    tags=["Auth"],
    responses={
        403: {"model": models.ErrorResponse},
        404: {"model": models.ErrorResponse},
        500: {"model": models.ErrorResponse},
    },
)
async def serve_reset_html(request: Request, token: str):
    try:
        user = await get_current_user(token)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return templates.TemplateResponse(request, "reset.html")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


###############################################
# App Specific changes for dynamic data
###############################################

ROOMS_FILE_PATH = os.path.join(os.path.dirname(__file__), "data", "rooms.json")

@lru_cache()
def read_rooms_data():
    """Reads and parses the rooms data from the JSON file."""
    try:
        # Check if the file exists
        if not os.path.exists(ROOMS_FILE_PATH):
            return HTTPException(status_code=500, detail="Error reading rooms data: File does not exist")
        
        with open(ROOMS_FILE_PATH, "r") as f:
            return json.load(f)
            
    except json.JSONDecodeError:
        # Handle cases where the JSON file is invalid
        print(f"Error decoding JSON from: {ROOMS_FILE_PATH}")
        raise HTTPException(status_code=500, detail="Error reading rooms data: Invalid JSON format")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while fetching rooms data")


@app.get(
    "/rooms",
    tags=["Dynamic Data"],
    responses={
        500: {"model": models.ErrorResponse},
    },
)
def get_rooms():
    """Returns the rooms data from data/rooms.json."""
    try:
        rooms_data = read_rooms_data()
        return rooms_data
        
    except HTTPException as e:
        # Re-raise the HTTPException raised by read_rooms_data
        raise e
    except Exception as e:
        # Catch any other unexpected errors
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    
    
SCHEDULE_FILE_PATH = os.path.join(os.path.dirname(__file__), "data", "schedule.json")

@lru_cache()
def read_schedule_data():
    """Reads and parses the full schedule data from the JSON file."""
    try:
        if not os.path.exists(SCHEDULE_FILE_PATH):
            return {"conference_days": [], "events": []}
        
        with open(SCHEDULE_FILE_PATH, "r") as f:
            data = json.load(f)
            return {
                "conference_days": data.get("conference_days", []),
                "events": data.get("events", [])
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error while fetching schedule data")


@app.get(
    "/schedule",
    tags=["Dynamic Data"],
    responses={
        500: {"model": models.ErrorResponse},
    },
)
def get_schedule():
    """Returns the full event schedule data including day metadata."""
    schedule_data = read_schedule_data()
    return schedule_data