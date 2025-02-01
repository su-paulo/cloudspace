import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta
from . import models, schemas, crud, database, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# Load the private and public keys
with open("/app/private_key.pem", "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

with open("/app/public_key.pem", "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Allow CORS for the frontend origin
origins = [
    "*",  # Adjust this to match your frontend's origin
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})

    # Convert private key to PEM format before encoding JWT
    private_key_pem = PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encode the JWT using the PEM format private key
    encoded_jwt = jwt.encode(to_encode, private_key_pem, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, username: str):
    user = crud.get_user_by_username(db, username=username.strip('"'))
    return user

def get_admin(db, username: str):
    admin = crud.get_admin_by_username(db, username=username.strip('"'))
    if admin:
        print(f"Retrieved admin: {admin.__dict__}")
    else:
        print("Retrieved admin: None")
    return admin

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not utils.verify_password(password, user.hashed_password):
        return False
    return user

def authenticate_admin(db: Session, username: str, password: str):
    admin = get_admin(db, username)
    if not admin:
        print(f"Admin {username} not found")
        return False
    if not utils.verify_password(password, admin.hashed_password):
        print(f"Password verification failed for admin {username}")
        return False
    return admin

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    admin = get_admin(db, username=username)
    if admin is None:
        raise credentials_exception
    return admin

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/admin/token", response_model=schemas.Token)
async def login_for_admin_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    print(f"Attempting to authenticate admin: {form_data.username}")
    admin = authenticate_admin(db, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": admin.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/v1/users/", response_model=schemas.User, dependencies=[Depends(oauth2_scheme)])
def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db), current_admin: schemas.Admin = Depends(get_current_admin)):
    return crud.create_user(db=db, user=user)

@app.get("/api/v1/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 10, db: Session = Depends(database.get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

@app.get("/api/v1/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(database.get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@app.delete("/api/v1/users/{user_id}", response_model=schemas.User, dependencies=[Depends(oauth2_scheme)])
def delete_user(user_id: int, db: Session = Depends(database.get_db), current_admin: schemas.Admin = Depends(get_current_admin)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return crud.delete_user(db=db, user_id=user_id)

@app.post("/api/v1/admins/", response_model=schemas.Admin, dependencies=[Depends(oauth2_scheme)])
def create_admin(admin: schemas.AdminCreate, db: Session = Depends(database.get_db), current_admin: schemas.Admin = Depends(get_current_admin)):
    return crud.create_admin(db=db, admin=admin)

@app.get("/api/v1/admins/", response_model=list[schemas.Admin], dependencies=[Depends(oauth2_scheme)])
def read_admins(skip: int = 0, limit: int = 10, db: Session = Depends(database.get_db), current_admin: schemas.Admin = Depends(get_current_admin)):
    admins = crud.get_admins(db, skip=skip, limit=limit)
    return admins

@app.get("/api/v1/admins/{admin_id}", response_model=schemas.Admin, dependencies=[Depends(oauth2_scheme)])
def read_admin(admin_id: int, db: Session = Depends(database.get_db), current_admin: schemas.Admin = Depends(get_current_admin)):
    db_admin = crud.get_admin(db, admin_id=admin_id)
    if db_admin is None:
        raise HTTPException(status_code=404, detail="Admin not found")
    return db_admin

@app.delete("/api/v1/admins/{admin_id}", response_model=schemas.Admin, dependencies=[Depends(oauth2_scheme)])
def delete_admin(admin_id: int, db: Session = Depends(database.get_db), current_admin: schemas.Admin = Depends(get_current_admin)):
    db_admin = crud.get_admin(db, admin_id=admin_id)
    if db_admin is None:
        raise HTTPException(status_code=404, detail="Admin not found")
    return crud.delete_admin(db=db, admin_id=admin_id)

# Function to convert public key to JWK format
def public_key_to_jwk(public_key):
    public_numbers = public_key.public_numbers()
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, byteorder='big')).decode('utf-8').rstrip("=")
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("=")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "1",
        "n": n,
        "e": e
    }

# Endpoint to expose JWKs
@app.get("/.well-known/jwks.json")
def get_jwks():
    jwk = public_key_to_jwk(PUBLIC_KEY)
    return {"keys": [jwk]}

# Create a default admin user if it doesn't exist
@app.on_event("startup")
async def create_default_admin():
    print("Executing create_default_admin function")
    try:
        db = next(database.get_db())
        admin_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
        admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
        admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "adminpassword")
        print(f"Admin credentials - Username: {admin_username}, Email: {admin_email}, Password: {admin_password}")
        admin = crud.get_admin_by_username(db, admin_username)
        if not admin:
            hashed_password = utils.get_password_hash(admin_password)
            admin_data = schemas.AdminCreate(
                username=admin_username,
                email=admin_email,
                password=admin_password
            )
            created_admin = crud.create_admin(db, admin_data)
            print(f"Default admin user created: {created_admin.__dict__}")
        else:
            print(f"Admin {admin_username} already exists: {admin.__dict__}")
    except Exception as e:
        print(f"Error creating default admin: {e}")