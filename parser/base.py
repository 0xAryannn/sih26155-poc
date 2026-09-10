"""
Common interface that all vendor/platform parsers implement.

Keeping this tiny on purpose - this is a POC. Every parser takes raw
config text and returns a models.ParsedConfig. No shared parsing logic
lives here; each parser is a real, independent implementation for its
platform's syntax.
"""

from abc import ABC, abstractmethod

from models import ParsedConfig


class BaseConfigParser(ABC):
    """Interface every vendor/platform parser must implement."""

    vendor: str
    platform: str

    @abstractmethod
    def parse(self, config_text: str) -> ParsedConfig:
        """Parse raw config text and return a populated ParsedConfig."""
        raise NotImplementedError
