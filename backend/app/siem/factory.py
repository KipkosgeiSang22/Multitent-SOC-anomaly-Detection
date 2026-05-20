"""
AdapterFactory — instantiates the correct SIEMAdapter for a client.
Handles credential decryption (Fernet) here so callers never deal with raw bytes.
"""
import json
import logging

from cryptography.fernet import Fernet

from .base import SIEMAdapter
from .graylog import GraylogAdapter
from .stubs import ElasticAdapter, WazuhAdapter, SplunkAdapter, SentinelAdapter

log = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    from app.core.config import settings
    key = settings.FERNET_KEY.encode()
    return Fernet(key)

_ADAPTER_MAP = {
    "graylog":   GraylogAdapter,
    "elastic":   ElasticAdapter,
    "wazuh":     WazuhAdapter,
    "splunk":    SplunkAdapter,
    "sentinel":  SentinelAdapter,
}


def _decrypt_creds(raw) -> dict:
    """
    Accept encrypted bytes/str from DB or already-decrypted dict.
    Returns plain dict {"username": ..., "password": ...}.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, memoryview):
        raw = bytes(raw)
    if isinstance(raw, str):
        raw = raw.encode()
    return json.loads(_get_fernet().decrypt(raw).decode())


def get_adapter(client: dict) -> SIEMAdapter:
    """
    Build and return the correct SIEMAdapter for a client dict
    (as returned by DB queries — keys: siem_type, siem_base_url, siem_credentials).

    Raises:
        ValueError  — unknown siem_type
        RuntimeError — missing base_url or FERNET_KEY
    """
    siem_type = (client.get("siem_type") or "").lower()
    base_url = client.get("siem_base_url") or ""
    raw_creds = client.get("siem_credentials")

    if not siem_type:
        raise ValueError(f"Client {client.get('id')} has no siem_type configured")
    if siem_type not in _ADAPTER_MAP:
        raise ValueError(
            f"Unknown siem_type '{siem_type}' for client {client.get('id')}. "
            f"Supported: {list(_ADAPTER_MAP.keys())}"
        )
    if not base_url:
        raise RuntimeError(f"Client {client.get('id')} has no siem_base_url configured")

    creds = _decrypt_creds(raw_creds) if raw_creds else {}
    adapter_cls = _ADAPTER_MAP[siem_type]
    log.debug("AdapterFactory: client=%s siem_type=%s → %s", client.get("id"), siem_type, adapter_cls.__name__)
    return adapter_cls(base_url, creds)