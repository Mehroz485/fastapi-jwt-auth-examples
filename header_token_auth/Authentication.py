from fastapi import FastAPI, Depends, Header, HTTPException
from jose import jwt
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext

app = FastAPI()

SECRET_KEY = "my_secret"
ALGORITHM = "HS256"

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


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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


@app.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()

    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_token({"sub": user.username})

    return {
        "access_token": token
    }


def verify_token(token: str = Header(None)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


@app.get("/secure")
def secure(user=Depends(verify_token)):
    return {
        "message": "secure data accessed",
        "user": user
    }