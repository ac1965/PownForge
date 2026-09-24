from __future__ import annotations

from pownforge.core.models import ManagedResource, ResourceStatus


class ResourceRegistry:
    """Tracks the side effects a single primitive run creates so cleanup can
    be driven and verified. In-memory per run; the final ManagedResource
    list is persisted as part of the PrimitiveRunRecord."""

    def __init__(self, owner: str) -> None:
        self._owner = owner
        self._resources: dict[str, ManagedResource] = {}

    def register(
        self, type: str, description: str = "", cleanup_required: bool = True
    ) -> ManagedResource:
        resource = ManagedResource(
            type=type, owner=self._owner, description=description, cleanup_required=cleanup_required
        )
        self._resources[resource.id] = resource
        return resource

    def mark(self, resource_id: str, status: ResourceStatus) -> None:
        self._resources[resource_id].status = status

    def resources(self) -> list[ManagedResource]:
        return list(self._resources.values())

    def pending_cleanup(self) -> list[ManagedResource]:
        return [
            r
            for r in self._resources.values()
            if r.cleanup_required and r.status != ResourceStatus.VERIFIED_ABSENT
        ]

    def residual(self) -> list[ManagedResource]:
        """Resources that still require cleanup but aren't verified absent --
        i.e. leaked or failed-to-clean. These become ResidualArtifact evidence."""
        return [
            r
            for r in self._resources.values()
            if r.cleanup_required and r.status != ResourceStatus.VERIFIED_ABSENT
        ]
