from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..models import Finding, TraceEvent, TraceState


class Detector(ABC):
    """A side-effect-free detector evaluated against one event and prior trace state."""

    name = "base"

    @abstractmethod
    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        raise NotImplementedError

