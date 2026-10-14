"""Thin adapters over existing NetShare state/core modules."""

from .file_index_adapter import FileIndexAdapter
from .network_adapter import NetworkAdapter
from .runtime_adapter import RuntimeAdapter
from .state_adapter import StateAdapter
from .web_session_adapter import WebSessionAdapter

__all__ = [
    "FileIndexAdapter", "NetworkAdapter", "RuntimeAdapter", "StateAdapter", "WebSessionAdapter"
]
