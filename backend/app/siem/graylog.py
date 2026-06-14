"""
GraylogAdapter — full implementation of SIEMAdapter for Graylog REST API.
Credentials are passed in already-decrypted form (dict with username/password).
"""
import logging
from typing import Any

import httpx

from .base import SIEMAdapter

log = logging.getLogger(__name__)

# Graylog returns messages nested under {"messages": [{"message": {...}}]}
_DEFAULT_FIELDS = (
    "timestamp,source,message,EventID,UserName,IpAddress,"
    "CommandLine,SubjectUserName,TargetUserName,WorkstationName,"
    "LogonType,ProcessName,ParentProcessName"
)
#TODO List: have field names in .env to override the DEFAULT_FIELDS 


class GraylogAdapter(SIEMAdapter):
    """
    Wraps the Graylog REST API.
    base_url  — e.g. http://graylog.internal:9000
    creds     — {"username": "...", "password": "..."}
    """

    def __init__(self, base_url: str, creds: dict):
        self.base_url = base_url.rstrip("/")
        self._auth = (creds.get("username", ""), creds.get("password", ""))
        self._headers = {"Accept": "application/json", "X-Requested-By": "soc-platform"}
        # Persistent client: one handshake, reused for all requests
        self._client = httpx.AsyncClient(
            auth=self._auth,
            headers=self._headers,
            timeout=30,
        )

    async def close(self):
        """Close the persistent HTTP client when all jobs are finished."""
        await self._client.aclose()

    # ── internal helpers ─────────────────────────────────────────────────────

    async def _get(self, path: str, params: dict | None = None) -> Any:
        resp = await self._client.get(f"{self.base_url}{path}", params=params or {})
        resp.raise_for_status()
        return resp.json()

    async def _post(self, path: str, body: dict) -> Any:
        resp = await self._client.post(f"{self.base_url}{path}", json=body)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    async def _delete(self, path: str) -> Any:
        resp = await self._client.delete(f"{self.base_url}{path}")
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    async def _put(self, path: str, body: dict) -> Any:
        resp = await self._client.put(f"{self.base_url}{path}", json=body)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    # ── SIEMAdapter implementation ──────────────────────────────────────────

    async def fetch_events(self, query: str, lookback_seconds: int, limit: int = 1000) -> list[dict]:
        """
        Call Graylog universal relative search.
        Returns list of flat message dicts (timestamp, source, EventID, etc.)
        """
        try:
            data = await self._get("/api/search/universal/relative", params={
                "query": query,
                "range": lookback_seconds,
                "limit": limit,
                "fields": _DEFAULT_FIELDS,
                "sort": "timestamp:desc",
            })
            data.raise_for_status()
            messages = data.get("messages", [])
            return [m["message"] for m in messages]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                log.error(
                    "Graylog authentication failed for %s — check credentials (401)",
                    self.base_url,
                )
            raise
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            log.error("Graylog connection error for %s: %s", self.base_url, e)
            raise       

    async def get_inputs(self) -> list[dict]:
        data = await self._get("/api/system/inputs")
        return data.get("inputs", [])

    async def restart_input(self, input_id: str) -> dict:
        # Graylog: DELETE to stop, PUT to start
        try:
            await self._delete(f"/api/system/inputs/{input_id}/launch")
        except httpx.HTTPStatusError:
            pass  # may already be stopped
        return await self._put(f"/api/system/inputs/{input_id}/launch", {})

    async def create_user(self, user_data: dict) -> dict:
        # Extract full_name and parse it cleanly into components
        full_name = user_data.get("full_name", "SOC User")
        name_parts = full_name.split(" ", 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else "User"

        # Build the exact dictionary structure Graylog demands (strictly avoiding 'full_name')
        graylog_payload = {
            "username": user_data.get("username"),
            "password": user_data.get("password"),
            "email": user_data.get("email"),
            "first_name": first_name,
            "last_name": last_name,
            "roles": user_data.get("roles", ["Reader"]),
            "permissions": user_data.get("permissions", []),
            "timezone": user_data.get("timezone", "Africa/Nairobi"),
            "session_timeout_ms": user_data.get("session_timeout_ms", 28800000),
        }

        return await self._post("/api/users", graylog_payload)

    async def delete_user(self, username: str) -> dict:
        return await self._delete(f"/api/users/{username}")

    async def get_dashboards(self) -> list[dict]:
        data = await self._get("/api/dashboards")
        return data.get("dashboards", [])

    async def create_dashboard(self, config: dict) -> dict:
        return await self._post("/api/dashboards", config)

    async def get_streams(self) -> list[dict]:
        data = await self._get("/api/streams")
        return data.get("streams", [])

    async def get_system_health(self) -> dict:
        """Aggregate node + index + input health."""
        try:
            overview = await self._get("/api/system")
            cluster = await self._get("/api/system/cluster/nodes")
            indices = await self._get("/api/system/indexer/overview")
            return {
                "status": overview.get("lifecycle", "unknown"),
                "version": overview.get("version"),
                "cluster_nodes": len(cluster.get("nodes", [])),
                "indices": indices,
            }
        except httpx.HTTPError as e:
            log.warning("Graylog health check failed: %s", e)
            return {"status": "unreachable", "error": str(e)}
