import os
from datetime import datetime,timedelta,timezone
import bcrypt
from jose import jwt,JWTError
SECRET_KEY=os.getenv('SECRET_KEY','aaa-academy-local-secret-change-me')
COOKIE_NAME='aaa_session'
def hash_password(p): return bcrypt.hashpw(p.encode(),bcrypt.gensalt()).decode()
def verify_password(p,h): return bcrypt.checkpw(p.encode(),h.encode())
def token(data):
    x=dict(data); x['exp']=datetime.now(timezone.utc)+timedelta(hours=12); return jwt.encode(x,SECRET_KEY,algorithm='HS256')
def decode(t):
    try:return jwt.decode(t,SECRET_KEY,algorithms=['HS256'])
    except JWTError:return None
