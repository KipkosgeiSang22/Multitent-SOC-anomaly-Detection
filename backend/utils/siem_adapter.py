from abc import ABC, abstractmethod
import time
import httpx
import pandas as pd

# ── 1. THE UNIFIED BLUEPRINT ──────────────────────────────────────────────────
class SIEMAdapter(ABC):
    @abstractmethod
    async def fetch_events(self, client_config: dict, query_string: str, lookback_minutes: int) -> pd.DataFrame:
        """Standardized contract that every SIEM engine must satisfy."""
        pass

# ── 2. THE EXISTING GRAYLOG WORKER ───────────────────────────────────────────
class GraylogAdapter(SIEMAdapter):
    async def fetch_events(self, client_config: dict, query_string: str, lookback_minutes: int) -> pd.DataFrame:
        creds = client_config.get("siem_credentials", {})
        base_url = client_config.get("siem_base_url")
        
        url = f"{base_url}/api/search/universal/relative"
        headers = {"Accept": "application/json"}
        auth = (creds.get("username"), creds.get("password"))
        
        params = {
            "query": query_string,
            "range": str(lookback_minutes * 60),  # Minutes to seconds
            "limit": 1000
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, auth=auth, timeout=30.0)
            if response.status_code != 200:
                raise Exception(f"Graylog API failure: Status {response.status_code}")
                
            messages = response.json().get("messages", [])
            rows = []
            for item in messages:
                msg = item.get("message", {})
                rows.append({
                    "timestamp": msg.get("timestamp"),
                    "source_host": msg.get("source", "unknown"),
                    "fields": {k: v for k, v in msg.items() if k not in ["timestamp", "source"]}
                })
            return pd.DataFrame(rows)

# ── 3. THE OPTIMIZED CACHING WAZUH WORKER ────────────────────────────────────
class WazuhAdapter(SIEMAdapter):
    def __init__(self):
        self._token_cache = None
        self._token_expiry = 0.0

    async def _get_valid_token(self, base_url: str, creds: dict) -> str:
        current_time = time.time()
        if self._token_cache and current_time < (self._token_expiry - 60):
            return self._token_cache

        url = f"{base_url}/api/security/user/authenticate"
        auth = (creds.get("username"), creds.get("password"))
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(url, auth=auth, timeout=10.0)
            if response.status_code != 200:
                raise Exception(f"Wazuh Auth Token exchange failed: {response.status_code}")
            
            token = response.json().get("data", {}).get("token")
            self._token_cache = token
            self._token_expiry = current_time + 900  # Token stays valid for 15 minutes
            return token

    async def fetch_events(self, client_config: dict, query_string: str, lookback_minutes: int) -> pd.DataFrame:
        creds = client_config.get("siem_credentials", {})
        base_url = client_config.get("siem_base_url")
        
        token = await self._get_valid_token(base_url, creds)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        params = {"limit": 1000, "q": query_string, "sort": "-timestamp"}
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(f"{base_url}/api/alerts", headers=headers, params=params, timeout=30.0)
            if response.status_code == 401:
                self._token_cache = None  # Evict broken token
                raise Exception("Wazuh Token expired or invalid.")
                
            alerts = response.json().get("data", {}).get("affected_items", [])
            rows = []
            for alert in alerts:
                rows.append({
                    "timestamp": alert.get("timestamp"),
                    "source_host": alert.get("agent", {}).get("name", "wazuh-agent"),
                    "fields": {
                        "EventID": alert.get("rule", {}).get("id"),
                        "Description": alert.get("rule", {}).get("description"),
                        **alert.get("data", {})
                    }
                })
            return pd.DataFrame(rows)

# ── 4. THE ROUTING FACTORY ────────────────────────────────────────────────────
class SIEMAdapterFactory:
    # Maintain instances in memory to preserve local class variables like Wazuh's token cache!
    _instances = {
        "graylog": GraylogAdapter(),
        "wazuh": WazuhAdapter()
    }

    @classmethod
    def get_adapter(cls, siem_type: str) -> SIEMAdapter:
        adapter = cls._instances.get(siem_type.lower())
        if not adapter:
            raise NotImplementedError(f"SIEM type '{siem_type}' is not supported yet.")
        return adapter