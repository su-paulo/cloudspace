from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    userid: str
    name: str
    alias: str
    email: str
    role: str

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

class AdminBase(BaseModel):
    username: str
    email: str

class AdminCreate(AdminBase):
    password: str

class Admin(AdminBase):
    id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None