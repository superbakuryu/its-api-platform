from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import uvicorn

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

db_user = [
    {
        "id": 0,
        "username": "admin",
        "email": "string",
        "password": "$2b$12$yffGYlhHbkBrpgkmAJxSs.sVjH17bEWRCHfeI4DEiiswmMmKa6vdC",
        "active": 1
    },
    {
        "id": 1,
        "username": "1",
        "email": "string",
        "password": "$2b$12$rMm2bUjYfx9huezJW3JVbuNPpFaV5DItvHeuu/sUsgpi.2OOM.Z8S",
        "active": 1
    },
    {
        "id": 2,
        "username": "2",
        "email": "string",
        "password": "$2b$12$i1VISKlCZA73JMyOUa1qCegTE06TMb.nReRL29FGcnP/5M52XEspS",
        "active": 0
    }
]
db_stt = [
    {
        "user_id": "1",
        "voice_log_id": "string",
        "task_id": "string",
        "call_id": "string",
        "msg": "string",
        "progress": 0,
        "status": 0,
        "audio_path": "string",
        "audio_path_local": "string",
        "processing_time": 0,
        "content": [
            1
        ],
        "update_at": "string",
        "result_pattern": {}
    },
    {
        "user_id": "2",
        "voice_log_id": "string",
        "task_id": "string",
        "call_id": "string",
        "msg": "string",
        "progress": 0,
        "status": 0,
        "audio_path": "string",
        "audio_path_local": "string",
        "processing_time": 0,
        "content": [
            1
        ],
        "update_at": "string",
        "result_pattern": {}
    },
    {
        "user_id": "3",
        "voice_log_id": "string",
        "task_id": "string",
        "call_id": "string",
        "msg": "string",
        "progress": 0,
        "status": 0,
        "audio_path": "string",
        "audio_path_local": "string",
        "processing_time": 0,
        "content": [
            1
        ],
        "update_at": "string",
        "result_pattern": {}
    }
]
db_voiceid = [
    {
        "user_id": "0",
        "avatar": "string",
        "name": "string",
        "email": "string",
        "phone": "string",
        "title": "string",
        "company": "string",
        "department": "string",
        "tags": [
            1
        ]
    },
    {
        "user_id": "1",
        "avatar": "string",
        "name": "string",
        "email": "string",
        "phone": "string",
        "title": "string",
        "company": "string",
        "department": "string",
        "tags": [
            1
        ]
    }
]


# DATABASE
class User(BaseModel):
    id: int
    username: str
    email: str
    password: str
    active: int


class STT(BaseModel):
    user_id: str
    voice_log_id: str
    task_id: str
    call_id: str
    msg: str
    progress: int
    status: int
    audio_path: str
    audio_path_local: str
    processing_time: float
    content: list
    update_at: str
    result_pattern: dict


class VoiceID(BaseModel):
    user_id: str
    update_at = str
    avatar: str
    name: str
    email: str
    phone: str
    title: str
    company: str
    department: str
    tags: list

class Service(BaseModel):
    service_id: int
    name: str
    price: int

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None

# END DATABASE


# FUNCTION
def get_voiceid(id):
    for element in db_voiceid:
        if element['user_id'] == id:
            return element
    return "Không có dữ liệu"


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    for user in db_user:
        if user['username'] == token_data.username:
            return user
    if user is None:
        raise credentials_exception


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user["active"]:
        return current_user
    raise HTTPException(status_code=400, detail="Inactive user")
# END FUNCTION


@app.post("/token", response_model=Token, tags=['Authentication'])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    for user in db_user:
        if user['username'] == form_data.username and verify_password(form_data.password, user['password']):
            access_token_expires = timedelta(
                minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user['username']}, expires_delta=access_token_expires)
            return {"access_token": access_token, "token_type": "bearer"}
            # return 'Pass'
    return "Sai tài khoản hoặc mật khẩu"


@app.get("/", tags=["Home"])
def read_root():
    return {"key": "value"}

# USER


@app.get("/user", tags=['User'])
def show_user(current_user: User = Depends(get_current_active_user)):
    return db_user


@app.post("/user", tags=['User'])
def create_user(request: User, current_user: User = Depends(get_current_active_user)):
    request.password = get_password_hash(request.password)
    db_user.append(request.dict())
    return request.dict()


@app.get('/user/{id}', tags=['User'])
def show_user(id: int, current_user: User = Depends(get_current_active_user)):
    for user in db_user:
        if user['id'] == id:
            return user
    return "Không tồn tại người dùng này"


# STTFILES
@app.get("/sttfiles", tags=['STT'])
def show_sttfiles():
    return db_stt


@app.post("/sttfiles", tags=['STT'])
def create_sttfile(sttfile: STT, current_user: User = Depends(get_current_active_user)):
    db_stt.append(sttfile.dict())
    return "Save thành công"


@app.delete("/sttfiles/{sttfile_id}", tags=['STT'])
def delete_sttfile(sttfile_id: int, current_user: User = Depends(get_current_active_user)):
    db_stt.pop(sttfile_id-1)
    return "Delete thành công"


# VOICEID
@app.get("/voiceid", tags=['VoiceID'])
def show_voiceid():
    return db_voiceid


@app.post("/voiceid", tags=['VoiceID'])
def create_voiceid(voiceid: VoiceID, current_user: User = Depends(get_current_active_user)):
    db_voiceid.append(voiceid.dict())
    return "Thêm thành công"


@app.get("/voiceid/{voiceid}", tags=['VoiceID'])
def show_voiceid(voiceid: str):
    return get_voiceid(voiceid)


@app.put("/voiceid/{user_id}", tags=['VoiceID'])
def update_voiceid(user_id: str, name: str, email: str, phone: str, current_user: User = Depends(get_current_active_user)):
    voiceid = get_voiceid(user_id)
    if type(voiceid) == str:
        return "Không tìm thấy ID"
    else:
        voiceid['name'] = name
        voiceid['email'] = email
        voiceid['phone'] = phone
        return "Update thành công"


@app.delete("/voiceid/{user_id}", tags=['VoiceID'])
def delete_voiceid(user_id: str, current_user: User = Depends(get_current_active_user)):
    voiceid = get_voiceid(user_id)
    if type(voiceid) == str:
        return "Không tìm thấy ID"
    else:
        db_voiceid.remove(voiceid)
        return "Xoá thành công"


# RUN
if __name__ == "__main__":
    uvicorn.run("main:app", port=8000, reload=True)
