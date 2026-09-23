"""Concrete validation primitives built on the core framework
(core/operation.py, core/models.py). Detection/validation-oriented only --
no exploit payloads or code execution (see docs/handbook.md §15)."""

from pownforge.primitives.http_interaction import (
    CallbackListener,
    HttpInteractionPrimitive,
    HttpSender,
    Interaction,
    ThreadedCallbackListener,
    UrllibSender,
)
from pownforge.primitives.jndi_lookup import (
    JndiLookupProbePrimitive,
    TcpCallbackListener,
    TcpInteraction,
    ThreadedTcpListener,
    UrllibHeaderSender,
)

__all__ = [
    "CallbackListener",
    "HttpInteractionPrimitive",
    "HttpSender",
    "Interaction",
    "JndiLookupProbePrimitive",
    "TcpCallbackListener",
    "TcpInteraction",
    "ThreadedCallbackListener",
    "ThreadedTcpListener",
    "UrllibHeaderSender",
    "UrllibSender",
]
