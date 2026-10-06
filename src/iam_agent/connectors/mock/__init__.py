"""Mock estate simulator shared by every mock connector."""

from iam_agent.connectors.mock.store import MockStore, get_mock_store

__all__ = ["MockStore", "get_mock_store"]
