import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./aaa_academy.db')
if DATABASE_URL.startswith('postgres://'): DATABASE_URL=DATABASE_URL.replace('postgres://','postgresql://',1)
connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {}
engine=create_engine(DATABASE_URL,connect_args=connect_args)
SessionLocal=sessionmaker(bind=engine,autocommit=False,autoflush=False)
Base=declarative_base()
def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
