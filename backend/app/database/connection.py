from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

db_url = settings.DATABASE_URL
# Normalize postgres:// to postgresql:// if needed for SQLAlchemy compatibility
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
}

if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    engine_kwargs["connect_args"] = connect_args

    # SQLite foreign key enforcement
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
else:
    # PostgreSQL / Neon connection settings
    engine_kwargs["pool_recycle"] = 300
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20

engine = create_engine(db_url, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI Dependency for database session management."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Isolated Simulator Sandbox Database Engine
# Ensures attack simulation test executions cannot contaminate live development SOC inventory or sessions
sim_db_url = getattr(settings, "SIMULATOR_DATABASE_URL", "sqlite:///./simulator_sandbox.db")
if sim_db_url.startswith("postgres://"):
    sim_db_url = sim_db_url.replace("postgres://", "postgresql://", 1)

sim_engine_kwargs = {"pool_pre_ping": True}
if sim_db_url.startswith("sqlite"):
    sim_engine_kwargs["connect_args"] = {"check_same_thread": False}

simulator_engine = create_engine(sim_db_url, **sim_engine_kwargs)
if sim_db_url.startswith("sqlite"):
    @event.listens_for(simulator_engine, "connect")
    def set_sim_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

SimulatorSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=simulator_engine)
_simulator_schema_initialized = False


def get_simulator_db():
    """FastAPI Dependency providing an isolated sandbox database for attack simulations."""
    global _simulator_schema_initialized
    if not _simulator_schema_initialized:
        from app.database.base import Base
        Base.metadata.create_all(bind=simulator_engine)
        _simulator_schema_initialized = True
    db = SimulatorSessionLocal()
    try:
        yield db
    finally:
        db.close()

