class FirebreakError(Exception):
    """Base class for controlled Firebreak failures."""


class ProtocolError(FirebreakError, ValueError):
    """Untrusted input failed protocol validation."""


class ContainmentError(FirebreakError, RuntimeError):
    """A local containment or atomic-state operation failed."""
