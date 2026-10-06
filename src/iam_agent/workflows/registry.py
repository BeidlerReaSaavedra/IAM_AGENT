"""Workflow registry: maps a workflow key to its implementation."""

from __future__ import annotations

from typing import Any

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.workflows.base import Workflow
from iam_agent.workflows.offboarding import DeferredDeletionWorkflow, OffboardingWorkflow
from iam_agent.workflows.onboarding import OnboardingWorkflow
from iam_agent.workflows.transfer import TransferWorkflow

WORKFLOW_CLASSES: dict[str, type[Workflow]] = {
    OnboardingWorkflow.key: OnboardingWorkflow,
    OffboardingWorkflow.key: OffboardingWorkflow,
    TransferWorkflow.key: TransferWorkflow,
    DeferredDeletionWorkflow.key: DeferredDeletionWorkflow,
}


class WorkflowRegistry:
    """Instantiates workflows against a shared connector hub."""

    def __init__(self, hub: ConnectorHub, settings: Settings) -> None:
        self.hub = hub
        self.settings = settings
        self._cache: dict[str, Workflow] = {}

    def get(self, key: str) -> Workflow:
        if key not in WORKFLOW_CLASSES:
            raise KeyError(
                f"unknown workflow '{key}'. Available: {', '.join(sorted(WORKFLOW_CLASSES))}"
            )
        if key not in self._cache:
            self._cache[key] = WORKFLOW_CLASSES[key](self.hub, self.settings)
        return self._cache[key]

    def keys(self) -> list[str]:
        return sorted(WORKFLOW_CLASSES)

    def describe_all(self) -> list[dict[str, Any]]:
        return [self.get(k).describe() for k in self.keys()]

    def has(self, key: str) -> bool:
        return key in WORKFLOW_CLASSES


__all__ = [
    "WorkflowRegistry",
    "WORKFLOW_CLASSES",
    "Workflow",
    "OnboardingWorkflow",
    "OffboardingWorkflow",
    "TransferWorkflow",
    "DeferredDeletionWorkflow",
]
