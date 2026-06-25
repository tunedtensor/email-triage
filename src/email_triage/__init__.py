"""Local email safety triage."""

__version__ = "0.1.0"

from .api import triage, triage_batch
from .harness import EmailInput, EmailTriageHarness

__all__ = ["EmailInput", "EmailTriageHarness", "triage", "triage_batch"]
