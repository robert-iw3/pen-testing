# backend/schemas.py
from pydantic import BaseModel
from typing import Optional, List

class TokenResponse(BaseModel):
    token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str

class OperatorCreate(BaseModel):
    username: str
    password: str
    role: str  # "admin" or "operator"

class OperatorUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None

class OperatorOut(BaseModel):
    id: str
    username: str
    role: str

class NewListenerRequest(BaseModel):
    type: str
    bind_ip: str
    port: int
    profile: str | None = None
    certfile: str | None = None
    keyfile: str | None = None
    name: str | None = None


class ListenerOut(BaseModel):
    id: str
    type: str
    bind_ip: str
    port: int
    status: str
    profile: str | None = None
    name: str | None = None

class SessionSummary(BaseModel):
    id: str
    hostname: str = ""
    user: str = ""
    os: str = ""
    arch: str = ""
    transport: str = ""
    integrity: str = ""
    last_checkin: Optional[float] = None

class FileInfo(BaseModel):
    name: str
    is_dir: bool
    size: Optional[int] = None
