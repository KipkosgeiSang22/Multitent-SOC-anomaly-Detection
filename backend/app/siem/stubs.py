"""
Stub adapters for future SIEM integrations.
All methods raise NotImplementedError — structure is ready, implementation pending.
"""
from .base import SIEMAdapter


class _NotImplementedAdapter(SIEMAdapter):
    _name: str = "unknown"
    def __init__(self, base_url: str, creds: dict):
        raise TypeError("_NotImplementedAdapter cannot be instantiated directly.")

    def _ni(self, method: str):
        raise NotImplementedError(
            f"{self._name} adapter: '{method}' is not yet implemented. "
            "Only Graylog is currently supported."
        )

    async def fetch_events(self, query, lookback_seconds, limit=500):      self._ni("fetch_events")
    async def get_inputs(self):                                             self._ni("get_inputs")
    async def restart_input(self, input_id):                               self._ni("restart_input")
    async def create_user(self, user_data):                                self._ni("create_user")
    async def delete_user(self, username):                                 self._ni("delete_user")
    async def get_dashboards(self):                                        self._ni("get_dashboards")
    async def create_dashboard(self, config):                              self._ni("create_dashboard")
    async def get_streams(self):                                           self._ni("get_streams")
    async def get_system_health(self):                                     self._ni("get_system_health")


class ElasticAdapter(_NotImplementedAdapter):
    _name = "ElasticSearch/OpenSearch"

    def __init__(self, base_url: str, creds: dict):
        self.base_url = base_url
        self._creds = creds


class WazuhAdapter(_NotImplementedAdapter):
    _name = "Wazuh"

    def __init__(self, base_url: str, creds: dict):
        self.base_url = base_url
        self._creds = creds


class SplunkAdapter(_NotImplementedAdapter):
    _name = "Splunk"

    def __init__(self, base_url: str, creds: dict):
        self.base_url = base_url
        self._creds = creds


class SentinelAdapter(_NotImplementedAdapter):
    _name = "Microsoft Sentinel"

    def __init__(self, base_url: str, creds: dict):
        self.base_url = base_url
        self._creds = creds
