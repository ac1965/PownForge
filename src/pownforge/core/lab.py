from __future__ import annotations

import json
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from pownforge.core.identifiers import IdentifierError, validate_identifier
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
        try:
            validate_identifier(name, kind="lab host")
        except IdentifierError as exc:
            raise LabError(str(exc)) from exc
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


def kind_kubeconfig_path(kubeconfig_dir: Path, name: str) -> Path:
    """Where a kind cluster's exported kubeconfig is written. Shared by the CLI
    and the web API so the layout rule lives in one place."""
    return kubeconfig_dir / f"{name}.kubeconfig"


# Default plugins a kind-registered Kubernetes target is authorized for.
KIND_DEFAULT_ALLOWED_PLUGINS = ["kubernetes", "kubernetes-audit", "kube-bench"]


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
        try:
            validate_identifier(name, kind="kind cluster")
        except IdentifierError as exc:
            raise LabError(str(exc)) from exc
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


# --------------------------------------------------------------------------
# External lab providers (docs/handbook.md §7). A LabProvider manages the
# *lifecycle* of externally-authored vulnerable environments (e.g. Vulhub's
# per-CVE docker-compose scenarios) -- list/start/status/stop/reset/cleanup --
# and nothing more. PownForge never runs an exploit against them: they are
# started as controlled targets, then assessed with the ordinary
# discovery/vuln-confirm plugins and validation primitives (see AGENTS.md's
# "PownForge自身はexploitを実行しない" invariant). Starting a scenario runs a
# deliberately-vulnerable container with whatever ports its compose file
# publishes, so it is meant for an isolated lab host.
# --------------------------------------------------------------------------


def vulhub_target_name(scenario_id: str) -> str:
    """Scope-target name for a Vulhub scenario, e.g.
    "log4j/CVE-2021-44228" -> "vulhub-log4j-cve-2021-44228". Shared by the CLI
    and the web API so the naming rule lives in one place."""
    slug = scenario_id.strip("/").lower().replace("/", "-").replace("_", "-")
    return f"vulhub-{slug}"


@dataclass
class PublishedPort:
    service: str
    host_port: int
    container_port: int


@dataclass
class LabScenario:
    id: str  # provider-relative identifier, e.g. "log4j/CVE-2021-44228"
    path: str  # absolute path to the scenario's compose directory
    running: bool = False
    published_ports: list[PublishedPort] = field(default_factory=list)


class LabProvider(ABC):
    """Lifecycle manager for an external catalogue of vulnerable
    environments. Concrete providers shell out to their orchestrator (docker
    compose, etc.) but never assess or exploit -- that stays with the plugins
    and primitives operating on the registered Target."""

    @abstractmethod
    def list_scenarios(self) -> list[LabScenario]: ...

    @abstractmethod
    def start(self, scenario_id: str) -> LabScenario: ...

    @abstractmethod
    def status(self, scenario_id: str) -> LabScenario: ...

    @abstractmethod
    def stop(self, scenario_id: str) -> None: ...

    @abstractmethod
    def reset(self, scenario_id: str) -> LabScenario: ...

    @abstractmethod
    def cleanup(self, scenario_id: str) -> None: ...


def _force_localhost_port(entry: Any) -> Any:
    """Rewrite one `ports:` list entry (Compose short or long syntax) so
    its host side is explicitly 127.0.0.1, regardless of what it already
    said (including an explicit "0.0.0.0"). Used only by
    VulhubProvider._localhost_only_up_command() -- see its docstring.

    Short syntax ("HOST:CONTAINER", optionally "/tcp"|"/udp" suffixed) has
    exactly one colon when no host IP is already present; that's the only
    case rewritten to prepend "127.0.0.1:". A bare container-only port
    (e.g. "80", no colon at all -- Compose then picks a random host port)
    is left as-is: Vulhub itself doesn't use this form (checked across
    the scenarios this feature was verified against), and there's no host
    port here yet to bind to a specific interface. An entry that already
    has 2+ colons (an existing host-ip:host-port:container-port) has its
    host-ip segment replaced. The long (mapping) syntax gets/overwrites a
    `host_ip` key the same way."""
    if isinstance(entry, str):
        if entry.count(":") == 1:
            return f"127.0.0.1:{entry}"
        parts = entry.split(":")
        if len(parts) >= 3:
            return "127.0.0.1:" + ":".join(parts[1:])
        return entry
    if isinstance(entry, dict):
        entry = dict(entry)
        entry["host_ip"] = "127.0.0.1"
        return entry
    return entry


def _extract_declared_host_port(entry: Any) -> int | None:
    """The fixed host port a single `ports:` entry declares, or None if it
    doesn't declare one (a bare container-only port like "80", or a value
    yaml.safe_load can't parse as a plain int, e.g. `"${PORT}:80"` env-var
    interpolation -- Compose resolves that at runtime, not here). Used only
    by _declared_port_order() below."""
    if isinstance(entry, str):
        spec = entry.split("/", 1)[0]  # drop an optional "/tcp"|"/udp" suffix
        parts = spec.split(":")
        if len(parts) < 2:
            return None
        try:
            return int(parts[-2])
        except ValueError:
            return None
    if isinstance(entry, dict):
        published = entry.get("published")
        if published is None:
            return None
        try:
            return int(published)
        except (TypeError, ValueError):
            return None
    return None


def _declared_port_order(compose_file: Path) -> list[int]:
    """Host ports in the order COMPOSE_FILE's own `services:` declare them
    (service iteration order, then each service's `ports:` list order).

    `docker compose ps --format json`'s own row/Publisher order does not
    reliably match this -- confirmed via real-machine testing against
    Vulhub's log4j/CVE-2021-44228, whose file lists 8983 (the Solr admin
    port the scenario's own PoC targets) before 5005 (a JDWP debug port),
    but `ps` reported 5005 first. `lab_provider start --register`
    (cli/lab_provider.py) blindly registers `published_ports[0]` as the
    scan target, so that ordering mismatch silently registered the wrong
    port. VulhubProvider._reorder_by_compose_declaration() uses this list
    to put `status()`'s published_ports back in the file's own order."""
    try:
        data = yaml.safe_load(compose_file.read_text()) or {}
    except (yaml.YAMLError, OSError):
        return []
    order: list[int] = []
    for service in (data.get("services") or {}).values():
        for entry in service.get("ports") or []:
            port = _extract_declared_host_port(entry)
            if port is not None:
                order.append(port)
    return order


class VulhubProvider(LabProvider):
    """LabProvider over a local Vulhub checkout (github.com/vulhub/vulhub).
    Each scenario is a directory containing a docker-compose file; the
    scenario id is its path relative to the checkout root (e.g.
    "log4j/CVE-2021-44228"). Vulhub is treated as an external catalogue --
    it is never vendored into PownForge, only pointed at."""

    def __init__(self, root: Path, runner: Runner = subprocess.run) -> None:
        self._root = root
        self._runner = runner

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise LabError(
                f"'{command[0]}' is required for `pownforge lab provider` but was not found on PATH. "
                "Install Docker (Desktop or Engine, which provides `docker compose`)."
            ) from exc

    def _compose_file(self, scenario_id: str) -> Path:
        # Reject traversal so a scenario id can't point outside the checkout.
        scenario_dir = (self._root / scenario_id).resolve()
        if self._root.resolve() not in scenario_dir.parents and scenario_dir != self._root.resolve():
            raise LabError(f"scenario '{scenario_id}' is outside the Vulhub root {self._root}")
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            candidate = scenario_dir / name
            if candidate.exists():
                return candidate
        raise LabError(
            f"no docker-compose file for scenario '{scenario_id}' under {self._root} "
            "(is --vulhub-dir pointing at a Vulhub checkout?)"
        )

    def _compose(self, scenario_id: str, *args: str) -> subprocess.CompletedProcess[str]:
        compose_file = self._compose_file(scenario_id)
        return self._run(["docker", "compose", "-f", str(compose_file), *args])

    def list_scenarios(self) -> list[LabScenario]:
        if not self._root.exists():
            raise LabError(
                f"Vulhub root {self._root} does not exist; clone github.com/vulhub/vulhub "
                "and pass --vulhub-dir (or set POWNFORGE_VULHUB_DIR)."
            )
        seen: set[str] = set()
        scenarios: list[LabScenario] = []
        for pattern in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            for compose in self._root.rglob(pattern):
                scenario_dir = compose.parent
                scenario_id = str(scenario_dir.relative_to(self._root))
                if scenario_id in seen:
                    continue
                seen.add(scenario_id)
                scenarios.append(LabScenario(id=scenario_id, path=str(scenario_dir)))
        return sorted(scenarios, key=lambda s: s.id)

    def _parse_ports(self, scenario_id: str) -> tuple[bool, list[PublishedPort]]:
        result = self._compose(scenario_id, "ps", "--format", "json")
        if result.returncode != 0:
            return False, []
        ports: list[PublishedPort] = []
        running = False
        # `docker compose ps --format json` emits either a JSON array or one
        # JSON object per line depending on the Compose version; handle both.
        text = result.stdout.strip()
        rows: list[dict[str, Any]] = []
        if text.startswith("["):
            try:
                rows = json.loads(text)
            except json.JSONDecodeError:
                rows = []
        else:
            for line in text.splitlines():
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        for row in rows:
            running = True
            service = row.get("Service", "")
            for pub in row.get("Publishers") or []:
                published = pub.get("PublishedPort")
                if published:
                    ports.append(
                        PublishedPort(
                            service=service,
                            host_port=int(published),
                            container_port=int(pub.get("TargetPort", published)),
                        )
                    )
        return running, ports

    def status(self, scenario_id: str) -> LabScenario:
        compose_file = self._compose_file(scenario_id)
        running, ports = self._parse_ports(scenario_id)
        ports = self._reorder_by_compose_declaration(compose_file, ports)
        return LabScenario(id=scenario_id, path=str(compose_file.parent), running=running, published_ports=ports)

    @staticmethod
    def _reorder_by_compose_declaration(compose_file: Path, ports: list[PublishedPort]) -> list[PublishedPort]:
        """Put PORTS (as `docker compose ps` returned them) back into the
        order COMPOSE_FILE's own `ports:` declarations use, so
        `published_ports[0]` -- what `lab_provider start --register` and
        `pownforge lab provider start --register` treat as "the" port --
        is deterministic and matches the scenario author's intent instead
        of `docker compose ps`'s own row order. A port not found in the
        declared order (an unparseable entry, e.g. env-var interpolated)
        keeps its original relative position, appended after every
        matched port -- see _declared_port_order()."""
        order = _declared_port_order(compose_file)
        if not order:
            return ports
        rank = {port: i for i, port in enumerate(order)}
        fallback_base = len(order)
        indexed = sorted(enumerate(ports), key=lambda pair: rank.get(pair[1].host_port, fallback_base + pair[0]))
        return [port for _, port in indexed]

    def start(self, scenario_id: str) -> LabScenario:
        # Vulhub's own compose files publish ports as plain "HOST:CONTAINER"
        # strings with no host IP (see e.g. log4j/CVE-2021-44228's
        # "8983:8983") -- Docker then binds the host side on *every*
        # interface, not just loopback (confirmed empirically: Docker
        # Desktop for Mac listens on `*:<port>`, reachable from the LAN,
        # not `127.0.0.1:<port>`). docs/handbook.md §7's "isolated lab
        # host" precondition for running an intentionally vulnerable
        # scenario is undermined if PownForge itself reintroduces network
        # exposure this way, so `up` always runs against a rewritten copy
        # of the compose file with every published port forced to
        # 127.0.0.1 -- never against Vulhub's own file, and never mutating
        # the checkout (the rewritten file is a throwaway temp file;
        # `--project-directory` keeps relative volume/build paths in the
        # compose file resolving against the real scenario directory).
        command, tmp_compose = self._localhost_only_up_command(scenario_id)
        try:
            result = self._run(command)
        finally:
            tmp_compose.unlink(missing_ok=True)
        if result.returncode != 0:
            raise LabError(f"failed to start scenario '{scenario_id}': {result.stderr.strip()}")
        return self.status(scenario_id)

    def _localhost_only_up_command(self, scenario_id: str) -> tuple[list[str], Path]:
        """Build the `docker compose up -d` argv for SCENARIO_ID against a
        rewritten copy of its compose file (every `ports:` entry forced to
        bind 127.0.0.1), plus the path of that temp file so the caller can
        remove it once the command has run. See `start()` for why."""
        compose_file = self._compose_file(scenario_id)
        data = yaml.safe_load(compose_file.read_text()) or {}
        for service in (data.get("services") or {}).values():
            ports = service.get("ports")
            if ports:
                service["ports"] = [_force_localhost_port(entry) for entry in ports]
        fd, tmp_name = tempfile.mkstemp(prefix="pownforge-vulhub-", suffix=".yml")
        tmp_path = Path(tmp_name)
        try:
            with open(fd, "w") as handle:
                yaml.safe_dump(data, handle, sort_keys=False)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        command = [
            "docker", "compose", "-f", str(tmp_path),
            "--project-directory", str(compose_file.parent),
            "up", "-d",
        ]
        return command, tmp_path

    def stop(self, scenario_id: str) -> None:
        result = self._compose(scenario_id, "stop")
        if result.returncode != 0:
            raise LabError(f"failed to stop scenario '{scenario_id}': {result.stderr.strip()}")

    def reset(self, scenario_id: str) -> LabScenario:
        # down (remove containers/networks) then up -d for a clean slate.
        down = self._compose(scenario_id, "down")
        if down.returncode != 0:
            raise LabError(f"failed to reset scenario '{scenario_id}': {down.stderr.strip()}")
        return self.start(scenario_id)

    def cleanup(self, scenario_id: str) -> None:
        # -v removes named volumes too, so no vulnerable state is left behind.
        result = self._compose(scenario_id, "down", "-v", "--remove-orphans")
        if result.returncode != 0:
            raise LabError(f"failed to clean up scenario '{scenario_id}': {result.stderr.strip()}")
