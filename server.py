from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Header
from starlette.responses import RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone, timedelta

import os
import re
import ipaddress
import logging
import secrets
import bcrypt
import jwt
import httpx
import resend
import uuid

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")
logger = logging.getLogger(__name__)

# ---- Config ----
EMAIL_FROM_NAME = os.environ["EMAIL_FROM_NAME"]
OWNER_EMAIL = os.environ["OWNER_EMAIL"]
EMAIL_REPLY_TO = os.environ.get("EMAIL_REPLY_TO")
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "Admin")
EMERGENT_AUTH_URL = "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data"
resend.api_key = os.environ["RESEND_API_KEY"]

# ==================== GOOGLE OAUTH ====================

oauth = OAuth()

google_client_id = os.environ["GOOGLE_CLIENT_ID"]
google_client_secret = os.environ["GOOGLE_CLIENT_SECRET"]
google_redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]

oauth.register(
    name="google",
    client_id=google_client_id,
    client_secret=google_client_secret,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    },
)


# ==================== EMAIL (guardrail gate + send) ====================
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)


class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan(); scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks the recipient for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links/assets must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Shortened, numeric-host or credential-bearing URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text {m.group(1)!r} != real link host {real!r} (G3)")


async def send_email(
    *,
    to: str,
    subject: str,
    html: str,
    reply_to: Optional[str] = None
) -> Optional[str]:
    _assert_safe_email(subject, html)

    try:
        params = {
            "from": f"{EMAIL_FROM_NAME} <{OWNER_EMAIL}>",
            "to": [to],
            "subject": subject,
            "html": html,
        }

        contact = reply_to or EMAIL_REPLY_TO
        if contact:
            params["reply_to"] = contact

        email = await resend.Emails.send_async(params)

        return email.get("id") if isinstance(email, dict) else getattr(email, "id", None)

    except Exception as e:
        logger.error(f"Resend email failed: {str(e)}")
        raise HTTPException(
            status_code=502,
            detail="Failed to send email"
        )


def _email_shell(inner: str) -> str:
    return (
        '<table role="presentation" width="100%" style="background:#050505;margin:0">'
        '<tr><td style="padding:32px;font-family:Arial,Helvetica,sans-serif;color:#F4F4F5">'
        '<div style="max-width:560px;margin:0 auto;border:1px solid rgba(255,255,255,0.1);padding:32px">'
        f'{inner}'
        '<p style="font-size:12px;color:#71717a;margin-top:28px">Envoyé par HollowCorp. '
        'Nous ne demandons jamais de mot de passe ni de coordonnées bancaires par email.</p>'
        '</div></td></tr></table>'
    )


# ==================== AUTH HELPERS ====================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, role: str) -> str:
    payload = {"sub": user_id, "role": role, "type": "access",
               "exp": datetime.now(timezone.utc) + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_jwt_cookie(response: Response, token: str):
    response.set_cookie(key="access_token", value=token, httponly=True, secure=True,
                        samesite="none", path="/", max_age=7 * 24 * 60 * 60)


class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    role: str = "client"


async def _user_public(user_doc) -> User:
    return User(user_id=user_doc["user_id"], email=user_doc["email"],
                name=user_doc.get("name") or user_doc["email"],
                picture=user_doc.get("picture"), role=user_doc.get("role", "client"))


async def resolve_current_user(request: Request, authorization: Optional[str]) -> Optional[dict]:
    # 1) JWT access token (email/password + admin)
    jwt_token = request.cookies.get("access_token")
    bearer = None
    if authorization and authorization.startswith("Bearer "):
        bearer = authorization.split(" ", 1)[1]
    for candidate in (jwt_token, bearer):
        if not candidate:
            continue
        try:
            payload = jwt.decode(candidate, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get("type") == "access":
                doc = await db.users.find_one({"user_id": payload["sub"]}, {"_id": 0})
                if doc:
                    return doc
        except jwt.PyJWTError:
            pass
    # 2) Google session_token cookie or bearer
    for token in (request.cookies.get("session_token"), bearer):
        if not token:
            continue
        session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
        if not session:
            continue
        expires_at = session["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            continue
        doc = await db.users.find_one({"user_id": session["user_id"]}, {"_id": 0})
        if doc:
            return doc
    return None


async def get_current_user(request: Request, authorization: Optional[str] = Header(None)) -> User:
    doc = await resolve_current_user(request, authorization)
    if not doc:
        raise HTTPException(status_code=401, detail="Non authentifié")
    return await _user_public(doc)


ROLE_LEVEL = {"client": 0, "employee": 1, "manager": 2, "ceo": 3}
STAFF_ROLES = ("employee", "manager", "ceo")


def _lvl(role: str) -> int:
    return ROLE_LEVEL.get(role, 0)


async def require_staff(user: User = Depends(get_current_user)) -> User:
    if user.role not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Accès réservé au personnel")
    return user


async def require_manager(user: User = Depends(get_current_user)) -> User:
    if user.role not in ("manager", "ceo"):
        raise HTTPException(status_code=403, detail="Réservé aux managers et au CEO")
    return user


async def require_ceo(user: User = Depends(get_current_user)) -> User:
    if user.role != "ceo":
        raise HTTPException(status_code=403, detail="Réservé au CEO")
    return user


# ==================== MODELS ====================
class ContactCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    phone: Optional[str] = Field(None, max_length=40)
    project: Optional[str] = Field(None, max_length=80)
    message: str = Field(..., min_length=1, max_length=4000)


class RegisterInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=200)


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class AdminLoginInput(BaseModel):
    username: str
    code: str


class EmployeeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=200)
    role: str = "employee"


class StatusUpdate(BaseModel):
    status: str


class MessageInput(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


VALID_STATUSES = ["Reçu", "En cours", "Livré"]


# ==================== PUBLIC: CONTACT ====================
@api_router.get("/")
async def root():
    return {"message": "HollowCorp API"}


@api_router.post("/contact")
async def create_contact(payload: ContactCreate, request: Request, authorization: Optional[str] = Header(None)):
    # Link the request to the logged-in user (if any) so they can track it in their space
    owner_id = None
    try:
        current = await resolve_current_user(request, authorization)
        if current:
            owner_id = current["user_id"]
    except Exception:
        owner_id = None
    doc = {
        "id": str(uuid.uuid4()),
        "name": payload.name,
        "email": payload.email.lower(),
        "phone": payload.phone,
        "project": payload.project,
        "message": payload.message,
        "status": "Reçu",
        "owner_id": owner_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.contacts.insert_one(doc)

    # Notify the owner
    owner_html = _email_shell(
        '<p style="font-family:monospace;letter-spacing:2px;color:#FF2D2D;font-size:12px;margin:0 0 16px">HOLLOWCORP // NOUVEAU CONTACT</p>'
        f'<h1 style="font-size:22px;margin:0 0 24px">Demande de {escape(doc["name"])}</h1>'
        f'<p style="margin:6px 0;color:#A1A1AA"><strong style="color:#F4F4F5">Email :</strong> {escape(doc["email"])}</p>'
        f'<p style="margin:6px 0;color:#A1A1AA"><strong style="color:#F4F4F5">Téléphone :</strong> {escape(doc["phone"] or "—")}</p>'
        f'<p style="margin:6px 0;color:#A1A1AA"><strong style="color:#F4F4F5">Projet :</strong> {escape(doc["project"] or "—")}</p>'
        '<hr style="border:none;border-top:1px solid rgba(255,255,255,0.1);margin:20px 0">'
        f'<p style="margin:0;color:#F4F4F5;line-height:1.6;white-space:pre-wrap">{escape(doc["message"])}</p>'
    )
    try:
        await send_email(to=OWNER_EMAIL, subject=f"Nouvelle demande — {doc['name']}", html=owner_html)
    except Exception as e:
        logger.error(f"Owner notification email failed: {e}")

    # Confirmation to the visitor (transactional auto-reply, fixed template)
    try:
        confirm_html = _email_shell(
            '<p style="font-family:monospace;letter-spacing:2px;color:#FF2D2D;font-size:12px;margin:0 0 16px">HOLLOWCORP</p>'
            f'<h1 style="font-size:22px;margin:0 0 20px">Merci {escape(doc["name"])} !</h1>'
            '<p style="color:#A1A1AA;line-height:1.6;margin:0 0 16px">Nous avons bien reçu votre demande et '
            'reviendrons vers vous sous 48h. Voici un récapitulatif de votre message :</p>'
            f'<p style="color:#F4F4F5;line-height:1.6;white-space:pre-wrap;border-left:2px solid #FF2D2D;padding-left:14px;margin:0 0 16px">{escape(doc["message"])}</p>'
            '<p style="color:#A1A1AA;line-height:1.6;margin:0">À très vite,<br/>L\'équipe HollowCorp</p>'
        )
        await send_email(to=doc["email"], subject="HollowCorp — Nous avons bien reçu votre demande", html=confirm_html)
    except Exception as e:
        logger.error(f"Confirmation email failed: {e}")

    return {"status": "success", "id": doc["id"]}


# ==================== AUTH: EMAIL/PASSWORD ====================
@api_router.post("/auth/register")
async def register(payload: RegisterInput, response: Response):
    email = payload.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Un compte existe déjà avec cet email")
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    await db.users.insert_one({
        "user_id": user_id, "email": email, "name": payload.name,
        "password_hash": hash_password(payload.password), "role": "client",
        "auth_provider": "password", "created_at": datetime.now(timezone.utc).isoformat(),
    })
    set_jwt_cookie(response, create_access_token(user_id, "client"))
    return {"user_id": user_id, "email": email, "name": payload.name, "role": "client"}


@api_router.post("/auth/login")
async def login(payload: LoginInput, response: Response):
    email = payload.email.lower()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user or not user.get("password_hash") or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    set_jwt_cookie(response, create_access_token(user["user_id"], user.get("role", "client")))
    return {"user_id": user["user_id"], "email": user["email"],
            "name": user.get("name"), "role": user.get("role", "client")}


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    response.delete_cookie("session_token", path="/", samesite="none", secure=True)
    response.delete_cookie("access_token", path="/", samesite="none", secure=True)
    return {"status": "ok"}


@api_router.get("/auth/me", response_model=User)
async def auth_me(user: User = Depends(get_current_user)):
    return user


# ==================== AUTH: GOOGLE ====================

@api_router.get("/auth/google")
async def google_login(request: Request):
    # URL de callback enregistrée dans Google Cloud
    redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]

    return await oauth.google.authorize_redirect(
        request,
        redirect_uri,
    )


@api_router.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        # Récupération du token Google
        token = await oauth.google.authorize_access_token(request)

        # Récupération des informations utilisateur
        user_info = token.get("userinfo")

        if not user_info:
            raise HTTPException(
                status_code=401,
                detail="Impossible de récupérer les informations Google",
            )

        email = user_info.get("email")

        if not email:
            raise HTTPException(
                status_code=400,
                detail="Google n'a pas fourni d'adresse email",
            )

        email = email.lower()
        name = user_info.get("name") or email
        picture = user_info.get("picture")

        # Recherche du compte existant
        existing = await db.users.find_one(
            {"email": email},
            {"_id": 0},
        )

        if existing:
            user_id = existing["user_id"]
            role = existing.get("role", "client")

            await db.users.update_one(
                {"user_id": user_id},
                {
                    "$set": {
                        "name": name,
                        "picture": picture,
                    }
                },
            )

        else:
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            role = "client"

            await db.users.insert_one({
                "user_id": user_id,
                "email": email,
                "name": name,
                "picture": picture,
                "role": role,
                "auth_provider": "google",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

        # Création du JWT HollowCorp
        access_token = create_access_token(
            user_id,
            role,
        )

        # Redirection vers l'espace client
        redirect_response = RedirectResponse(
            url="https://hollowcorp.fr/espace-client",
            status_code=302,
        )

        # Cookie de connexion
        redirect_response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
            max_age=7 * 24 * 60 * 60,
        )

        return redirect_response

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Google OAuth failed: {e}")

        raise HTTPException(
            status_code=401,
            detail="Échec de la connexion Google",
        )

# ==================== ADMIN: rotating code login ====================
@api_router.post("/admin/request-code")
async def request_admin_code():
    code = f"{secrets.randbelow(1000000):06d}"
    await db.admin_codes.insert_one({
        "code": code, "used": False,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    html = _email_shell(
        '<p style="font-family:monospace;letter-spacing:2px;color:#FF2D2D;font-size:12px;margin:0 0 16px">HOLLOWCORP // ACCÈS ADMIN</p>'
        '<h1 style="font-size:20px;margin:0 0 16px">Votre code de connexion admin</h1>'
        f'<p style="font-size:38px;letter-spacing:8px;font-weight:bold;color:#FF2D2D;margin:0 0 16px">{code}</p>'
        '<p style="color:#A1A1AA;line-height:1.6;margin:0">Ce code est valable 10 minutes et à usage unique. '
        'Si vous n\'êtes pas à l\'origine de cette demande, ignorez cet email.</p>'
    )
    await send_email(to=OWNER_EMAIL, subject="HollowCorp — Code de connexion admin", html=html)
    return {"status": "sent", "email": OWNER_EMAIL}


@api_router.post("/admin/login")
async def admin_login(payload: AdminLoginInput, response: Response):
    if payload.username.strip().lower() != ADMIN_USERNAME.lower():
        raise HTTPException(status_code=401, detail="Identifiant ou code invalide")
    now = datetime.now(timezone.utc)
    doc = await db.admin_codes.find_one({"code": payload.code.strip(), "used": False}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=401, detail="Identifiant ou code invalide")
    exp = datetime.fromisoformat(doc["expires_at"])
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < now:
        raise HTTPException(status_code=401, detail="Code expiré, redemandez-en un")
    await db.admin_codes.update_one({"code": payload.code.strip()}, {"$set": {"used": True}})
    admin = await db.users.find_one({"role": {"$in": ["ceo", "admin"]}}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=500, detail="Compte CEO introuvable")
    set_jwt_cookie(response, create_access_token(admin["user_id"], "ceo"))
    return {"user_id": admin["user_id"], "email": admin["email"], "name": admin["name"], "role": "ceo"}


# ==================== STAFF: requests + support + employees ====================
@api_router.get("/admin/requests")
async def admin_requests(user: User = Depends(require_staff)):
    return await db.contacts.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)


@api_router.patch("/admin/requests/{req_id}")
async def update_request_status(req_id: str, payload: StatusUpdate, user: User = Depends(require_staff)):
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Statut invalide")
    res = await db.contacts.update_one({"id": req_id}, {"$set": {"status": payload.status}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Demande introuvable")
    return {"status": "ok", "new_status": payload.status}


@api_router.delete("/admin/requests/{req_id}")
async def delete_request(req_id: str, user: User = Depends(require_staff)):
    res = await db.contacts.delete_one({"id": req_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Demande introuvable")
    return {"status": "ok"}


@api_router.get("/admin/staff")
async def list_staff(user: User = Depends(require_manager)):
    return await db.users.find({"role": {"$in": ["employee", "manager"]}},
                               {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(500)


# Backwards-compatible alias used by the frontend team list
@api_router.get("/admin/employees")
async def list_employees(user: User = Depends(require_manager)):
    return await db.users.find({"role": {"$in": ["employee", "manager"]}},
                               {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(500)


@api_router.post("/admin/employees")
async def create_employee(payload: EmployeeCreate, user: User = Depends(require_manager)):
    new_role = payload.role if payload.role in ("employee", "manager") else "employee"
    # A manager can only recruit employees; only the CEO can create managers
    if new_role == "manager" and user.role != "ceo":
        raise HTTPException(status_code=403, detail="Seul le CEO peut créer un manager")
    email = payload.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Un compte existe déjà avec cet email")
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    await db.users.insert_one({
        "user_id": user_id, "email": email, "name": payload.name,
        "password_hash": hash_password(payload.password), "role": new_role,
        "auth_provider": "password", "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"user_id": user_id, "email": email, "name": payload.name, "role": new_role}


@api_router.delete("/admin/employees/{emp_id}")
async def delete_employee(emp_id: str, user: User = Depends(require_manager)):
    target = await db.users.find_one({"user_id": emp_id}, {"_id": 0})
    if not target or target.get("role") not in ("employee", "manager"):
        raise HTTPException(status_code=404, detail="Membre introuvable")
    # A manager can only remove employees; the CEO can remove employees and managers
    if _lvl(user.role) <= _lvl(target["role"]) and user.role != "ceo":
        raise HTTPException(status_code=403, detail="Droits insuffisants")
    if target["role"] == "manager" and user.role != "ceo":
        raise HTTPException(status_code=403, detail="Seul le CEO peut supprimer un manager")
    await db.users.delete_one({"user_id": emp_id})
    return {"status": "ok"}


@api_router.post("/admin/users/{target_id}/reset-password")
async def reset_user_password(target_id: str, user: User = Depends(require_staff)):
    target = await db.users.find_one({"user_id": target_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="Compte introuvable")
    if target.get("role") == "ceo":
        raise HTTPException(status_code=403, detail="Le mot de passe du CEO ne peut pas être réinitialisé ici")
    temp_password = secrets.token_urlsafe(9)
    await db.users.update_one({"user_id": target_id},
                              {"$set": {"password_hash": hash_password(temp_password),
                                        "auth_provider": "password"}})
    # Returned to staff to relay to the account owner (we never email plaintext passwords)
    return {"status": "ok", "email": target["email"], "temp_password": temp_password}


@api_router.get("/admin/support/threads")
async def support_threads(user: User = Depends(require_staff)):
    pipeline = [
        {"$sort": {"created_at": 1}},
        {"$group": {
            "_id": "$owner_id",
            "owner_name": {"$last": "$owner_name"},
            "owner_email": {"$last": "$owner_email"},
            "last_message": {"$last": "$body"},
            "last_at": {"$last": "$created_at"},
            "count": {"$sum": 1},
        }},
        {"$sort": {"last_at": -1}},
    ]
    rows = await db.support_messages.aggregate(pipeline).to_list(500)
    return [{"owner_id": r["_id"], "owner_name": r.get("owner_name"), "owner_email": r.get("owner_email"),
             "last_message": r.get("last_message"), "last_at": r.get("last_at"), "count": r.get("count")} for r in rows]


@api_router.get("/admin/support/threads/{owner_id}")
async def support_thread_messages(owner_id: str, user: User = Depends(require_staff)):
    return await db.support_messages.find({"owner_id": owner_id}, {"_id": 0}).sort("created_at", 1).to_list(1000)


@api_router.post("/admin/support/threads/{owner_id}")
async def support_thread_reply(owner_id: str, payload: MessageInput, user: User = Depends(require_staff)):
    owner = await db.users.find_one({"user_id": owner_id}, {"_id": 0})
    if not owner:
        raise HTTPException(status_code=404, detail="Client introuvable")
    msg = {
        "id": str(uuid.uuid4()), "owner_id": owner_id,
        "owner_name": owner.get("name"), "owner_email": owner.get("email"),
        "sender_id": user.user_id, "sender_name": user.name, "sender_role": user.role,
        "body": payload.body, "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.support_messages.insert_one(msg)
    msg.pop("_id", None)
    return msg


@api_router.delete("/admin/support/threads/{owner_id}")
async def delete_support_thread(owner_id: str, user: User = Depends(require_staff)):
    res = await db.support_messages.delete_many({"owner_id": owner_id})
    return {"status": "ok", "deleted": res.deleted_count}


# ==================== CLIENT: my requests + support ====================
@api_router.get("/my/requests")
async def my_requests(user: User = Depends(get_current_user)):
    query = {"$or": [{"owner_id": user.user_id}, {"email": user.email}]}
    return await db.contacts.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.get("/support/messages")
async def my_support(user: User = Depends(get_current_user)):
    return await db.support_messages.find({"owner_id": user.user_id}, {"_id": 0}).sort("created_at", 1).to_list(1000)


@api_router.post("/support/messages")
async def send_support(payload: MessageInput, user: User = Depends(get_current_user)):
    msg = {
        "id": str(uuid.uuid4()), "owner_id": user.user_id,
        "owner_name": user.name, "owner_email": user.email,
        "sender_id": user.user_id, "sender_name": user.name, "sender_role": user.role,
        "body": payload.body, "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.support_messages.insert_one(msg)
    msg.pop("_id", None)
    return msg


app.include_router(api_router)

app.add_middleware(
    SessionMiddleware,
    secret_key=JWT_SECRET,
    https_only=True,
    same_site="lax",
)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("user_id", unique=True)
    # Migrate any legacy "admin" role to "ceo"
    await db.users.update_many({"role": "admin"}, {"$set": {"role": "ceo"}})
    ceo = await db.users.find_one({"role": "ceo"})
    if not ceo:
        await db.users.insert_one({
            "user_id": f"user_{uuid.uuid4().hex[:12]}", "username": ADMIN_USERNAME,
            "email": OWNER_EMAIL.lower(), "name": "Admin", "role": "ceo",
            "auth_provider": "code", "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("CEO user seeded")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
