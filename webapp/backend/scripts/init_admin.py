import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.db.session import SessionLocal, engine, Base
from app.models.user import User
from app.core.security import get_password_hash
import getpass

Base.metadata.create_all(bind=engine)
db = SessionLocal()
try:
    admin = db.query(User).filter(User.role == "Administrator").first()
    if admin:
        print(f'Admin already exists: {admin.username}')
        sys.exit(0)
    username = input('Admin username: ')
    email = input('Admin email: ')
    password = getpass.getpass('Admin password: ')
    user = User(username=username, email=email, role='Administrator', hashed_password=get_password_hash(password), is_active=True)
    db.add(user)
    db.commit()
    print(f'Admin created: {username}')
finally:
    db.close()
