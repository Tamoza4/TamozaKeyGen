import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Override via environment variable in production:
#   DATABASE_URL=mysql+pymysql://user:pass@host:3306/dbname
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://root:password@localhost:3306/tamozakeygen",
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,   # drops stale connections before using them
    pool_recycle=1800,    # recycle connections every 30 min
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency that provides a per-request database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
