"""Base class every threat-intel provider inherits from."""

from __future__ import annotations

from typing import Optional

import requests

from ..models import IOCType, ProviderResult, Verdict

DEFAULT_TIMEOUT = 15


class BaseProvider:
    """A single threat-intel source.

    Subclasses set ``name``, ``categories`` (which IOC categories they support)
    and implement :meth:`_query`.
    """

    name: str = "base"
    categories: tuple = ()
    requires_key: bool = True

    def __init__(self, api_key: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    @property
    def enabled(self) -> bool:
        """True when the provider can actually run."""
        return bool(self.api_key) or not self.requires_key

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type.category in self.categories

    def query(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        """Public entry point with uniform error handling."""
        if not self.enabled:
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                success=False,
                verdict=Verdict.UNKNOWN,
                error="no API key configured (skipped)",
            )
        try:
            return self._query(ioc, ioc_type)
        except requests.exceptions.Timeout:
            return self._error(ioc, "request timed out")
        except requests.exceptions.RequestException as exc:
            return self._error(ioc, f"network error: {exc}")
        except Exception as exc:  # pragma: no cover - defensive catch-all
            return self._error(ioc, f"unexpected error: {exc}")

    # -- helpers for subclasses ------------------------------------------------

    def _query(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        raise NotImplementedError

    def _error(self, ioc: str, message: str) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=False,
            verdict=Verdict.ERROR,
            error=message,
        )
