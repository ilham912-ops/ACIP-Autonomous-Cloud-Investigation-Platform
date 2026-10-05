from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# En production, DATABASE_URL doit toujours venir de l'environnement
# (variable d'environnement EC2, secret manager, etc.). Le fallback local
# ci-dessous est fourni uniquement pour le développement et ne doit
# jamais contenir un vrai mot de passe s'il est amené à être commit.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://acip:changeme@localhost:5432/acip",
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,   # évite les erreurs sur connexions RDS fermées/expirées
    pool_size=5,
    max_overflow=10,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
