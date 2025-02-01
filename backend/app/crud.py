from sqlalchemy.orm import Session
from . import models, schemas, utils

# User CRUD operations
def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_users(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.User).offset(skip).limit(limit).all()

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.userid == username).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(
        userid=user.userid,
        name=user.name,
        alias=user.alias,
        email=user.email,
        role=user.role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    db.delete(db_user)
    db.commit()
    return db_user

# Admin CRUD operations
def get_admin(db: Session, admin_id: int):
    return db.query(models.Admin).filter(models.Admin.id == admin_id).first()

def get_admins(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Admin).offset(skip).limit(limit).all()

def get_admin_by_username(db: Session, username: str):
    print(f"Querying admin by username: {username}")
    admin = db.query(models.Admin).filter(models.Admin.username == username.strip('"')).first()
    if admin:
        print(f"Result of admin query: {admin}")
    else:
        print("Result of admin query: None")
    return admin

def create_admin(db: Session, admin: schemas.AdminCreate):
    hashed_password = utils.get_password_hash(admin.password)
    db_admin = models.Admin(
        username=admin.username,
        email=admin.email,
        hashed_password=hashed_password
    )
    db.add(db_admin)
    db.commit()
    db.refresh(db_admin)
    print(f"Admin created: {db_admin}")
    return db_admin

def delete_admin(db: Session, admin_id: int):
    db_admin = db.query(models.Admin).filter(models.Admin.id == admin_id).first()
    db.delete(db_admin)
    db.commit()
    return db_admin