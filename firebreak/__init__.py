"""Technocore Firebreak: untrusted content in, inert evidence out."""

from .consumer import consume_response
from .errors import ContainmentError, ProtocolError
from .models import CursorState, Event, IngestionResult

__all__ = [
    "ContainmentError",
    "CursorState",
    "Event",
    "IngestionResult",
    "ProtocolError",
    "consume_response",
]

__version__ = "0.2.0"
