from sqlalchemy.orm import Session
from . import models, schemas, crud, database, utils

def test_create_and_get_admin():
    # Create a new database session
    db: Session = next(database.get_db())

    # Define admin credentials
    admin_username = "admin"
    admin_email = "admin@example.com"
    admin_password = "adminpassword"

    # Create admin user
    hashed_password = utils.get_password_hash(admin_password)
    admin_data = schemas.AdminCreate(
        username=admin_username,
        email=admin_email,
        password=hashed_password
    )
    created_admin = crud.create_admin(db, admin_data)
    print(f"Admin user created: {created_admin.__dict__}")

    # Retrieve admin user by username
    admin = crud.get_admin_by_username(db, admin_username)
    print(f"Retrieved admin: {admin.__dict__ if admin else 'None'}")

if __name__ == "__main__":
    test_create_and_get_admin()