from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Callable

LAB_NETWORK = "pownforge-lab"
LAB_LABEL = "pownforge.lab=true"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class LabError(RuntimeError):
    """Raised when a lab network/container operation fails."""


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
        command = ["docker", "run", "-d", "--name", name, "--network", self._network]
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
