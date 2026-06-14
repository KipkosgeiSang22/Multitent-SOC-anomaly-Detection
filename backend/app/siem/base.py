"""
Abstract SIEM adapter interface.
All concrete adapters must implement every method.
"""
from abc import ABC, abstractmethod



class SIEMAdapter(ABC):

    @abstractmethod
    async def fetch_events(self, query: str, lookback_seconds: int, limit: int = 500) -> list[dict]:
        """Fetch raw event messages. Returns list of flat dicts (one per message)."""
        ...

    @abstractmethod
    async def get_inputs(self) -> list[dict]:
        """Return list of configured inputs/collectors."""
        ...

    @abstractmethod
    async def restart_input(self, input_id: str) -> dict:
        """Restart a specific input by ID."""
        ...

    @abstractmethod
    async def create_user(self, user_data: dict) -> dict:
        """Create a SIEM-level user."""
        ...

    @abstractmethod
    async def delete_user(self, username: str) -> dict:
        """Delete a SIEM-level user."""
        ...

    @abstractmethod
    async def get_dashboards(self) -> list[dict]:
        """Return list of dashboards."""
        ...

    @abstractmethod
    async def create_dashboard(self, config: dict) -> dict:
        """Create a dashboard from config."""
        ...

    @abstractmethod
    async def get_streams(self) -> list[dict]:
        """Return list of streams/indices."""
        ...

    @abstractmethod
    async def get_system_health(self) -> dict:
        """Return system health/status info."""
        ...
