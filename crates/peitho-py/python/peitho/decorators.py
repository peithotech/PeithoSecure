"""
PeithoSecure Python Decorators for AI Agent Tool Functions.
"""

from functools import wraps
from typing import Callable, Optional
import inspect

def shield(tool_name: Optional[str] = None, read_only: bool = True):
    """
    Decorator to gate an AI Agent tool function behind a PeithoSecure Capability Token.

    Example:
        @shield(tool_name="search_web", read_only=True)
        def search_web(query: str, token=None):
            return f"Results for: {query}"
    """
    def decorator(func: Callable):
        name = tool_name or func.__name__

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract token from kwargs or search args
            token = kwargs.get("token") or kwargs.get("_token")
            if token is None:
                raise PermissionError(f"PeithoSecure: Missing capability token for tool '{name}'")

            # Verify capability token
            token.verify(tool_name=name, is_read_only=read_only)

            return func(*args, **kwargs)

        return wrapper

    return decorator
