from fastapi import FastAPI, Depends, Header, HTTPException
from jose import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext

app = FastAPI()

SECRET_KEY = "my_secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_context = CryptContext(schemes=["bcrypt"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_passwords, hashed_password):
    return pwd_context.verify(plain_passwords, hashed_password)


def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return token


@app.post("/register")
def register(username: str, password: str, db: Session = Depends(get_db)):

    existing_user = db.query(User).filter(User.username == username).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )

    hashed_password = pwd_context.hash(password)

    new_user = User(username=username, hashed_password=hashed_password)

    db.add(new_user)

    db.commit()

    db.refresh(new_user)

    return {"message": "User registered successfully"}


from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):

    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Invalid username or password"
        )

    access_token = create_token({"sub": form_data.username})

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")


def verify_token(token: str = Depends(oauth2_schema)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username: str = payload.get("sub")

        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        return username

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )


@app.get("/secure")
def secure(user=Depends(verify_token)):

    return {
        "message": "secure data accessed",
        "user": user
    }