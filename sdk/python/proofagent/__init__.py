"""ProofAgent Python SDK — client-side keys, local signing, execution boundary."""

from .client import Client, Agent, ProofAgentError
from .boundary import ToolBoundary, ObservedExecution
from . import crypto_local

__all__ = [
    "Client",
    "Agent",
    "ProofAgentError",
    "ToolBoundary",
    "ObservedExecution",
    "crypto_local",
]
__version__ = "0.1.5"
