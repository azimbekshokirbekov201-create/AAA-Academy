import argparse
from datetime import datetime
from sqlalchemy import text
from app.database import engine
from app.auth import hash_password
p=argparse.ArgumentParser(); p.add_argument('--username',default='admin'); p.add_argument('--password',required=True); p.add_argument('--name',default='Admin'); a=p.parse_args()
with engine.begin() as c:
    hp=hash_password(a.password)
    c.execute(text('insert into admins(username,hashed_password,full_name,is_active,created_at) values(:u,:p,:n,1,:d)'),{'u':a.username,'p':hp,'n':a.name,'d':datetime.utcnow()})
    c.execute(text('insert into accounts(username,hashed_password,role,full_name,is_active,created_at) values(:u,:p,\'admin\',:n,1,:d)'),{'u':a.username,'p':hp,'n':a.name,'d':datetime.utcnow()})
print('Admin created:',a.username)
