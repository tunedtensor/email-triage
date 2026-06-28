"""Local email safety triage."""

__version__ = "0.3.2"

from .api import triage, triage_batch
from .harness import EmailInput, EmailTriageHarness

__all__ = ["EmailInput", "EmailTriageHarness", "__version__", "triage", "triage_batch"]
