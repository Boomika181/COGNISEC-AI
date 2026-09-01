from app.routes.auth import router as auth_router
from app.routes.users import router as users_router
from app.routes.sessions import router as sessions_router
from app.routes.behavior import router as behavior_router
from app.routes.security import router as security_router
from app.routes.admin import router as admin_router
from app.routes.demo import router as demo_router

__all__ = [
    "auth_router",
    "users_router",
    "sessions_router",
    "behavior_router",
    "security_router",
    "admin_router",
    "demo_router",
]
