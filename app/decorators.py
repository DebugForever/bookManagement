from flask_login import current_user
from functools import wraps
from flask import abort
from .models import Permission


def permission_required(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kw):
            if not current_user.can(permission):
                abort(403)
            return func(*args, **kw)

        return wrapper

    return decorator


def admin_required(func):
    return permission_required(Permission.ADMINISTER)(func)
