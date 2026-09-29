"""ProofAgent Python SDK — client-side keys, local receipt signing."""

from .client import Client, Agent, ProofAgentError
from . import crypto_local

__all__ = ["Client", "Agent", "ProofAgentError", "crypto_local"]
__version__ = "0.1.1"
