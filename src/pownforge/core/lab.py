from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from pownforge.core.models import TargetKind

LAB_NETWORK = "pownforge-lab"
LAB_LABEL = "pownforge.lab=true"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class LabError(RuntimeError):
    """Raised when a lab network/container operation fails."""


def resolve_lab_target_address(name: str, kind: TargetKind, scheme: str, port: int | None) -> str:
    """Build the scope address for a lab-registered target.

    Shared by the CLI `lab add` command and the web API's equivalent endpoint
    so the host/url-building rule lives in exactly one place.
    """
    if kind == TargetKind.URL:
        if port is None:
            raise LabError("a port is required when registering a 'url' kind target")
        return f"{scheme}://{name}:{port}"
    return name


@dataclass
class LabHost:
    name: str
    image: str
    status: str


class LabManager:
    """Starts/stops attack-target containers on an isolated Docker network.

    Docker calls are never issued directly by CLI code; everything goes
    through this class so the command-building and the actual subprocess
    execution stay testable in isolation (mirrors the Plugin split between
    build_command and execution).
    """

    def __init__(self, network: str = LAB_NETWORK, runner: Runner = subprocess.run) -> None:
        self._network = network
        self._runner = runner

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise LabError(
                f"'{command[0]}' is required for `pownforge lab` but was not found on PATH. "
                "Install Docker (Desktop or Engine) and make sure it's on PATH."
            ) from exc

    def ensure_network(self) -> None:
        inspect = self._run(["docker", "network", "inspect", self._network])
        if inspect.returncode == 0:
            return
        # --internal: lab hosts cannot route to the host's other networks or
        # the internet. Only skipped when the network already exists, so an
        # operator who created it differently on purpose is left alone.
        create = self._run(["docker", "network", "create", "--internal", self._network])
        if create.returncode != 0:
            raise LabError(
                f"failed to create lab network '{self._network}': {create.stderr.strip()}"
            )

    def add(self, name: str, image: str, env: dict[str, str] | None = None) -> LabHost:
        self.ensure_network()
        # -i (keep stdin open) matters for images whose default CMD ends in
        # an interactive shell after starting background services (a common
        # pattern in vulnerable-VM-to-container conversions, e.g. Metasploitable2
        # rebuilds using `services.sh && bash`) -- without it, that shell
        # reads EOF on stdin immediately and the whole container exits right
        # after `docker run -d`. Harmless for images that don't rely on this.
        command = ["docker", "run", "-d", "-i", "--name", name, "--network", self._network]
        command += ["--label", LAB_LABEL]
        for key, value in (env or {}).items():
            command += ["-e", f"{key}={value}"]
        command.append(image)

        result = self._run(command)
        if result.returncode != 0:
            raise LabError(f"failed to start lab host '{name}': {result.stderr.strip()}")
        return LabHost(name=name, image=image, status="running")

    def remove(self, name: str) -> None:
        result = self._run(["docker", "rm", "-f", name])
        if result.returncode != 0:
            raise LabError(f"failed to remove lab host '{name}': {result.stderr.strip()}")

    def list(self) -> list[LabHost]:
        result = self._run(
            ["docker", "ps", "-a", "--filter", f"label={LAB_LABEL}", "--format", "{{json .}}"]
        )
        if result.returncode != 0:
            raise LabError(f"failed to list lab hosts: {result.stderr.strip()}")

        hosts: list[LabHost] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            data: dict[str, Any] = json.loads(line)
            hosts.append(
                LabHost(
                    name=data.get("Names", ""),
                    image=data.get("Image", ""),
                    status=data.get("Status", ""),
                )
            )
        return hosts


def kind_context_name(cluster: str) -> str:
    """kubeconfig context name kind generates for a cluster; the `kubernetes`
    family of plugins use it as the target address."""
    return f"kind-{cluster}"


@dataclass
class KindCluster:
    name: str
    context: str
    kubeconfig: Path | None = None


class KindClusterManager:
    """Creates/deletes kind clusters and exports their in-docker-network kubeconfig.

    Like LabManager, this is the only place `kind` is shelled out to. The
    kubeconfig written by create() is `kind get kubeconfig --internal`,
    whose server is `<cluster>-control-plane:6443` on kind's docker network,
    not the host-facing 127.0.0.1 address -- the pownforge container can't
    reach the host from pownforge-lab (see docs/handbook.md §7).
    """

    def __init__(self, runner: Runner = subprocess.run) -> None:
        self._runner = runner

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise LabError(
                f"'{command[0]}' is required for `pownforge lab kind` but was not found on PATH. "
                "Install kind (https://kind.sigs.k8s.io/) and make sure it's on PATH."
            ) from exc

    def create(
        self, name: str, kubeconfig_path: Path, kind_config: Path | None = None
    ) -> KindCluster:
        command = ["kind", "create", "cluster", "--name", name]
        if kind_config is not None:
            command += ["--config", str(kind_config)]
        result = self._run(command)
        if result.returncode != 0:
            raise LabError(f"failed to create kind cluster '{name}': {result.stderr.strip()}")

        self.export_kubeconfig(name, kubeconfig_path)
        return KindCluster(name=name, context=kind_context_name(name), kubeconfig=kubeconfig_path)

    def export_kubeconfig(self, name: str, kubeconfig_path: Path) -> None:
        result = self._run(["kind", "get", "kubeconfig", "--internal", "--name", name])
        if result.returncode != 0:
            raise LabError(
                f"failed to export kubeconfig for kind cluster '{name}': {result.stderr.strip()}"
            )
        kubeconfig_path.parent.mkdir(parents=True, exist_ok=True)
        kubeconfig_path.write_text(result.stdout)
        # Contains the cluster's admin client key.
        kubeconfig_path.chmod(0o600)

    def delete(self, name: str) -> None:
        result = self._run(["kind", "delete", "cluster", "--name", name])
        if result.returncode != 0:
            raise LabError(f"failed to delete kind cluster '{name}': {result.stderr.strip()}")

    def list(self) -> list[KindCluster]:
        result = self._run(["kind", "get", "clusters"])
        if result.returncode != 0:
            raise LabError(f"failed to list kind clusters: {result.stderr.strip()}")
        return [
            KindCluster(name=line.strip(), context=kind_context_name(line.strip()))
            for line in result.stdout.splitlines()
            if line.strip()
        ]
